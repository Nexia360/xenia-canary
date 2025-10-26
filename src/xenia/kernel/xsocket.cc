/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik.
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "src/xenia/kernel/xsocket.h"

#include <cstring>
#include <unordered_map>  // for FSM future map

#include "xenia/base/platform.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/xam/xam_module.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_threading.h"

#include "xenia/kernel/XLiveAPI.h"

using namespace std::chrono_literals;

namespace xe {
namespace kernel {

// ====================== Local statics for FSM task management =================
// We keep the async FSM future entirely within this .cc file so we don't need
// to change the header. Keyed by the socket instance pointer.
static std::mutex g_fsm_tasks_mtx;
static std::unordered_map<XSocket*, std::future<void>> g_fsm_tasks;
// ==============================================================================

void XSocket::SetRecvCallback(std::function<void(const uint8_t*, uint32_t, const sockaddr*, int)> callback) {
  recv_callback_ = std::move(callback);
}

XSocket::XSocket(KernelState* kernel_state)
    : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() { Close(); }

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::X_IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::X_IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  // Set the receive buffer size to 1MB
  int recv_buf_size = 1024 * 1024;
  setsockopt(native_handle_, SOL_SOCKET, SO_RCVBUF, (const char*)&recv_buf_size, sizeof(recv_buf_size));

  // Set the send buffer size to 1MB
  int send_buf_size = 1024 * 1024;
  setsockopt(native_handle_, SOL_SOCKET, SO_SNDBUF, (const char*)&send_buf_size, sizeof(send_buf_size));

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
  // Signal overlapped paths as closing.
  {
    std::unique_lock send_lock(send_mutex_);
    if (send_active_overlapped_ &&
        !(send_active_overlapped_->offset_high & (uint32_t)WSAInfo::complete)) {
      send_active_overlapped_->offset_high |= (uint32_t)WSAInfo::closed;
    }
  }
  {
    std::unique_lock receive_lock(receive_mutex_);
    if (receive_active_overlapped_ &&
        !(receive_active_overlapped_->offset_high & (uint32_t)WSAInfo::complete)) {
      receive_active_overlapped_->offset_high |= (uint32_t)WSAInfo::closed;
    }
  }

  // Stop FSM first so it won't touch the socket while we close.
  StopNetFsm_();

  std::unique_lock send_socket_lock(send_socket_mutex_);
  std::unique_lock receive_socket_lock(receive_socket_mutex_);
#if XE_PLATFORM_WIN32
  int ret = closesocket(native_handle_);
#elif XE_PLATFORM_LINUX
  int ret = close(native_handle_);
#endif
  send_socket_lock.unlock();
  receive_socket_lock.unlock();

  if (ret != 0) {
    XELOGE("Failed to close socket with error: {}", GetLastWSAError());
    return X_STATUS_UNSUCCESSFUL;
  }

  // Ensure the socket is unbound and resources are released
  native_handle_ = -1;
  bound_ = false;
  bound_port_ = 0;

  // Reset rings.
  recv_ring_.reset();
  send_ring_.reset();

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::GetOption(uint32_t level, uint32_t optname, void* optval_ptr,
                            uint32_t* optlen) {
  int ret =
      getsockopt(native_handle_, level, optname, static_cast<char*>(optval_ptr),
                 reinterpret_cast<socklen_t*>(optlen));

  // Because values provided in optval_ptr are in LE we must somehow save
  // them in BE.
  switch (*optlen) {
    case 1:
      xe::copy_and_swap<uint8_t>((uint8_t*)optval_ptr, (uint8_t*)optval_ptr, 1);
      break;
    case 4:
      xe::copy_and_swap<uint32_t>((uint32_t*)optval_ptr, (uint32_t*)optval_ptr,
                                  1);
      break;
    case 8:
      xe::copy_and_swap<uint64_t>((uint64_t*)optval_ptr, (uint64_t*)optval_ptr,
                                  1);
      break;
    default:
      XELOGE("XSocket::GetOption - Unhandled optlen: {}", *optlen);
      break;
  }

  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }
  return X_STATUS_SUCCESS;
}

static void* GetOptValueWithProperEndianness(void* optval_ptr, uint32_t optname,
                                             uint32_t optlen) {
  // No special BE/LE handling needed at the moment beyond common sizes.
  (void)optname;
  switch (optlen) {
    case 1:
    case 4:
    case 8:
    default:
      return optval_ptr;
  }
}

X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr,
                            uint32_t optlen) {
  if (level == 0xFFFF && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  void* proper_ptr =
      GetOptValueWithProperEndianness(optval_ptr, optname, optlen);

  int ret = setsockopt(native_handle_, level, optname, (const char*)proper_ptr,
                       optlen);

  if (optval_ptr != proper_ptr) {
    free(proper_ptr);
  }

  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  // SO_BROADCAST
  if (level == 0xFFFF && optname == 0x0020) {
    broadcast_socket_ = true;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
#ifdef XE_PLATFORM_WIN32
  int ret = ioctlsocket(native_handle_, cmd, (u_long*)arg_ptr);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }
  return X_STATUS_SUCCESS;
#elif XE_PLATFORM_LINUX
  return X_STATUS_UNSUCCESSFUL;
#endif
}

X_STATUS XSocket::Connect(const XSOCKADDR_IN* name, int name_len) {
  XSOCKADDR_IN sa_in = XSOCKADDR_IN();
  memcpy(&sa_in, name, sizeof(XSOCKADDR_IN));

  sa_in.address_port =
      XLiveAPI::upnp_handler->GetMappedConnectPort(name->address_port);

  sockaddr addr = sa_in.to_host();

  int ret = connect(native_handle_, &addr, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(const XSOCKADDR_IN* name, int name_len) {
  XSOCKADDR_IN sa_in = XSOCKADDR_IN();
  memcpy(&sa_in, name, sizeof(XSOCKADDR_IN));

  sa_in.address_port =
      XLiveAPI::upnp_handler->GetMappedBindPort(name->address_port);

  sockaddr addr = sa_in.to_host();

  int ret = bind(native_handle_, &addr, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_port_ = sa_in.address_port;

  if (!bound_port_) {
    XSOCKADDR_IN sa = *name;
    if (!GetSockName(&sa, &name_len)) {
      bound_port_ = sa.address_port;
    }
  }

  bound_ = true;

  // Start the FSM loop once the socket is bound.
  StartNetFsm_();

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }
  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(XSOCKADDR_IN* name, int* name_len) {
  sockaddr sa = {};
  int addrlen = 0;
  const bool is_name_and_name_len_available = name && name_len;

  if (is_name_and_name_len_available) {
    addrlen = byte_swap(*name_len);
  }

  const uint64_t ret = accept(native_handle_, name ? &sa : nullptr,
                              name_len ? &addrlen : nullptr);
  if (ret == -1) {
    return nullptr;
  }

  if (is_name_and_name_len_available) {
    name->to_guest(&sa);
    *name_len = byte_swap(addrlen);
  }

  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) { return shutdown(native_handle_, how); }

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  int ret = recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
  if (ret > 0 && recv_callback_) {
    sockaddr addr;
    int addrlen = sizeof(addr);
    getpeername(native_handle_, &addr, &addrlen);
    recv_callback_(buf, ret, &addr, addrlen);
  }
  return ret;
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags,
                      XSOCKADDR_IN* from, uint32_t* from_len) {
  sockaddr sa{};
  if (from) {
    sa = from->to_host();
  }
  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len,
                     flags, from ? &sa : nullptr, (int*)from_len);
  if (from) {
    from->to_guest(&sa);
  }
  return ret;
}

struct WSASendToData {
  XWSABUF* buffers;
  uint32_t num_buffers;
  uint32_t flags;
  XSOCKADDR_IN* to;
  uint32_t to_len;
  XWSAOVERLAPPED* overlapped;
};

struct WSARecvFromData {
  XWSABUF* buffers;
  uint32_t num_buffers;
  uint32_t flags;
  XSOCKADDR_IN* from;
  xe::be<uint32_t>* from_len;
  XWSAOVERLAPPED* overlapped;
};

// =============================== FSM Helpers ===============================

bool XSocket::TryEnqueueSend_(const uint8_t* buf, uint32_t len,
                              const sockaddr* addr, int addrlen) {
  if (!buf || !len) return false;
  NetPacket pkt{};
  if (addr) {
    std::memcpy(&pkt.addr, addr, sizeof(sockaddr));
    pkt.addrlen = addrlen;
  } else {
    pkt.addr = {};
    pkt.addrlen = 0;
  }
  pkt.len = static_cast<uint16_t>(std::min<uint32_t>(len, sizeof(pkt.data)));
  std::memcpy(pkt.data, buf, pkt.len);
  bool ok = send_ring_.push(pkt);
  if (ok) {
    // Wake FSM
    std::lock_guard<std::mutex> lk(fsm_cv_mtx_);
    fsm_cv_.notify_all();
  }
  return ok;
}

bool XSocket::TryDequeueRecv_(uint8_t* buf, uint32_t buf_len, uint32_t* out_len,
                              sockaddr* out_addr, int* out_addrlen) {
  if (!buf || !out_len) return false;
  NetPacket pkt{};
  if (!recv_ring_.pop(pkt)) return false;

  const uint32_t n = std::min<uint32_t>(buf_len, pkt.len);
  std::memcpy(buf, pkt.data, n);
  *out_len = n;

  if (out_addr && out_addrlen) {
    std::memcpy(out_addr, &pkt.addr, sizeof(sockaddr));
    *out_addrlen = pkt.addrlen;
  }
  return true;
}

void XSocket::FsmDoNetSend_() {
  // Drain send ring to the OS socket.
  NetPacket pkt{};
  while (send_ring_.pop(pkt)) {
    int ret = 0;
    if (pkt.addrlen > 0) {
      ret = ::sendto(native_handle_, reinterpret_cast<const char*>(pkt.data),
                     pkt.len, 0, &pkt.addr, pkt.addrlen);
    } else {
      ret = ::send(native_handle_, reinterpret_cast<const char*>(pkt.data),
                   pkt.len, 0);
    }
    (void)ret;  // errors are non-fatal for UDP, we drop silently
  }
}

void XSocket::FsmDoNetRecv_() {
#ifdef XE_PLATFORM_WIN32
  // Read any pending datagrams into the recv ring (non-blocking).
  WSAPOLLFD pfd{};
  pfd.fd = native_handle_;
  pfd.events = POLLIN;
  int pr = WSAPoll(&pfd, 1, 0);
  if (pr <= 0) return;
#endif

  // Pull a few datagrams per tick to avoid starvation.
  for (int i = 0; i < 32; ++i) {
    NetPacket pkt{};
    pkt.addrlen = sizeof(sockaddr);
    int got = ::recvfrom(native_handle_, reinterpret_cast<char*>(pkt.data),
                         sizeof(pkt.data), 0, &pkt.addr, &pkt.addrlen);
    if (got <= 0) break;
    pkt.len = static_cast<uint16_t>(got);
    // If ring full, drop packet.
    (void)recv_ring_.push(pkt);
  }
}

void XSocket::StartNetFsm_() {
  if (fsm_started_) return;
  fsm_wants_exit_.store(false, std::memory_order_relaxed);
  fsm_state_.store(NetFsmState::Running, std::memory_order_release);
  fsm_started_ = true;

  // Launch FSM like other async tasks in this file.
  std::future<void> fut =
      std::async(std::launch::async, &XSocket::NetFsmLoop_, this);

  {
    std::lock_guard<std::mutex> lk(g_fsm_tasks_mtx);
    g_fsm_tasks[this] = std::move(fut);
  }
}

void XSocket::StopNetFsm_() {
  if (!fsm_started_) return;
  fsm_wants_exit_.store(true, std::memory_order_release);
  {
    std::lock_guard<std::mutex> lk(fsm_cv_mtx_);
    fsm_cv_.notify_all();
  }

  std::future<void> fut;
  {
    std::lock_guard<std::mutex> lk(g_fsm_tasks_mtx);
    auto it = g_fsm_tasks.find(this);
    if (it != g_fsm_tasks.end()) {
      fut = std::move(it->second);
      g_fsm_tasks.erase(it);
    }
  }
  if (fut.valid()) {
    fut.wait();
  }

  fsm_started_ = false;
  fsm_state_.store(NetFsmState::Idle, std::memory_order_release);
}

void XSocket::NetFsmLoop_() {
#ifdef XE_PLATFORM_WIN32
  WSAPOLLFD pfd{};
  pfd.fd = native_handle_;
  pfd.events = POLLIN | POLLOUT;
#endif

  while (!fsm_wants_exit_.load(std::memory_order_acquire)) {
#ifdef XE_PLATFORM_WIN32
    (void)WSAPoll(&pfd, 1, 1);
#else
    // POSIX: could use poll() with short timeout if needed.
#endif
    FsmDoNetSend_();
    FsmDoNetRecv_();

    if (send_ring_.empty() && recv_ring_.empty()) {
      std::unique_lock<std::mutex> lk(fsm_cv_mtx_);
      fsm_cv_.wait_for(lk, 1ms);
    }
  }
}

// ============================ WSA (FSM-first) ==============================

int XSocket::WSASendTo(XWSABUF* buffers, uint32_t num_buffers,
                       xe::be<uint32_t>* num_bytes_sent_ptr, uint32_t flags,
                       XSOCKADDR_IN* to_ptr, uint32_t to_len,
                       XWSAOVERLAPPED* overlapped_ptr) {
  if (!buffers || !num_buffers || !num_bytes_sent_ptr || flags ||
      (to_ptr && (to_len < sizeof(XSOCKADDR_IN) ||
                  to_ptr->address_family != X_AF_INET))) {
    SetLastWSAError(X_WSAError::X_WSA_INVALID_PARAMETER);
    return -1;
  }

  // Prefer FSM ring for UDP/VDP datagrams.
  bool can_use_fsm = (type_ == X_SOCK_DGRAM || proto_ == X_IPPROTO_UDP ||
                      proto_ == X_IPPROTO_VDP) &&
                     to_ptr;

  uint32_t total_len = 0;
  for (uint32_t i = 0; i < num_buffers; ++i) total_len += buffers[i].len;

  if (can_use_fsm && total_len <= 1500) {
    // Translate destination first.
    sockaddr addr = to_ptr->to_host();

    // Flatten SG into a small stack buffer and enqueue into the send ring.
    uint8_t stackbuf[1500];
    uint32_t off = 0;
    for (uint32_t i = 0; i < num_buffers; ++i) {
      auto* src = reinterpret_cast<const uint8_t*>(
          kernel_state()->memory()->TranslateVirtual(buffers[i].buf_ptr));
      std::memcpy(stackbuf + off, src, buffers[i].len);
      off += buffers[i].len;
    }

    if (TryEnqueueSend_(stackbuf, total_len, &addr, (int)to_len)) {
      // Immediate completion through FSM path.
      if (num_bytes_sent_ptr) *num_bytes_sent_ptr = total_len;
      if (overlapped_ptr) {
        overlapped_ptr->internal = total_len;
        overlapped_ptr->internal_high = 0;
        overlapped_ptr->offset_high |= WSAInfo::complete;
        overlapped_ptr->offset = flags;
        if (overlapped_ptr->event_handle) {
          xboxkrnl::xeNtSetEvent(overlapped_ptr->event_handle, nullptr);
        }
      }
      SetLastWSAError((X_WSAError)0);
      return 0;  // success
    } else {
      // Ring full → signal pending if overlapped; else EWOULDBLOCK.
      if (overlapped_ptr) {
        overlapped_ptr->offset_high |= WSAInfo::sendto_flag;
        SetLastWSAError(X_WSAError::X_WSA_IO_PENDING);
        return -1;
      } else {
        SetLastWSAError(X_WSAError::X_WSAEWOULDBLOCK);
        return -1;
      }
    }
  }

  // ===== Legacy path (poll/send) when FSM can’t be used =====
  WSASendToData send_async_data = {};
  send_async_data.buffers = buffers;
  send_async_data.num_buffers = num_buffers;
  send_async_data.flags = flags;
  send_async_data.to = to_ptr;
  send_async_data.to_len = to_len;

  XWSAOVERLAPPED tmp_overlapped = {};
  send_async_data.overlapped =
      overlapped_ptr ? overlapped_ptr : &tmp_overlapped;

  if (overlapped_ptr) {
    overlapped_ptr->offset_high |= WSAInfo::sendto_flag;
  }

  int ret = PushWSASendTo(false, send_async_data);

  if (ret < 0) {
    auto wsa_error = send_async_data.overlapped->internal_high.get();
    SetLastWSAError((X_WSAError)wsa_error);

    if (overlapped_ptr &&
        wsa_error == (uint32_t)X_WSAError::X_WSAEWOULDBLOCK) {
      std::lock_guard<std::mutex> lk(send_mutex_);

      if (!send_active_overlapped_ ||
          (send_active_overlapped_->offset_high & WSAInfo::complete)) {
        // Copy stack-based buffers
        send_async_data.buffers = new XWSABUF[num_buffers];
        std::memcpy(send_async_data.buffers, buffers,
                    num_buffers * sizeof(XWSABUF));

        overlapped_ptr->offset_high |= WSAInfo::sendto_flag;

        if (overlapped_ptr->event_handle) {
          xboxkrnl::xeNtClearEvent(overlapped_ptr->event_handle);
        }

        send_active_overlapped_ = overlapped_ptr;

        if (!send_task_.valid()) {
          send_task_ = std::async(std::launch::async, &XSocket::PushWSASendTo,
                                  this, true, send_async_data);
        } else {
          auto status = send_task_.wait_for(0ms);
          if (status == std::future_status::ready) {
            (void)send_task_.get();
          }
        }
        SetLastWSAError(X_WSAError::X_WSA_IO_PENDING);
      }
    }
  } else {
    if (num_bytes_sent_ptr) {
      *num_bytes_sent_ptr = send_async_data.overlapped->internal;
    }
  }

  return ret;
}

int XSocket::PushWSASendTo(bool wait, WSASendToData send_async_data) {
  send_async_data.overlapped->internal_high = 0;

  WSAPOLLFD fds = {};
  fds.fd = native_handle_;
  fds.events = POLLOUT;

  DWORD bytes_sent = 0;
  DWORD flags = send_async_data.flags;
  WSABUF* buffers = new WSABUF[send_async_data.num_buffers];

  sockaddr addr = send_async_data.to->to_host();

  int ret;
  do {
#ifdef XE_PLATFORM_WIN32
    ret = WSAPoll(&fds, 1, wait ? 1000 : 0);
#else
    ret = poll(&fds, 1, wait ? 1000 : 0);
#endif

    if (send_async_data.overlapped->offset_high & WSAInfo::closed) {
      send_async_data.overlapped->internal_high =
          (uint32_t)X_WSAError::X_WSA_OPERATION_ABORTED;
      ret = -1;
      goto threadexit;
    }
  } while (ret == 0 && wait);

  if (ret < 0) {
    send_async_data.overlapped->internal_high = GetLastWSAError();
    XELOGE("XSocket send thread failed with error {}",
           static_cast<uint32_t>(send_async_data.overlapped->internal_high));
    goto threadexit;
  } else if (ret == 0) {
    send_async_data.overlapped->internal_high =
        (uint32_t)X_WSAError::X_WSAEWOULDBLOCK;
    ret = -1;
    goto threadexit;
  }

#ifdef XE_PLATFORM_WIN32
  for (uint32_t i = 0; i < send_async_data.num_buffers; i++) {
    buffers[i].len = send_async_data.buffers[i].len;
    buffers[i].buf =
        reinterpret_cast<CHAR*>(kernel_state()->memory()->TranslateVirtual(
            send_async_data.buffers[i].buf_ptr));
  }

  ret = ::WSASendTo(native_handle_, buffers, send_async_data.num_buffers,
                    &bytes_sent, send_async_data.flags, &addr,
                    send_async_data.to_len, nullptr, nullptr);
  if (ret < 0) {
    send_async_data.overlapped->internal_high = GetLastWSAError();
    switch (send_async_data.overlapped->internal_high) {
      case WSAEMSGSIZE:
      case WSAENETDOWN:
      case WSAEHOSTDOWN:
      case WSAEHOSTUNREACH:
      case WSAENETRESET:
      case WSAECONNABORTED:
      case WSAECONNRESET:
      case WSAENOTCONN:
      case WSAESHUTDOWN:
      case WSAETIMEDOUT:
        XELOGE("WSASendTo failed with UDP-specific error {}",
               static_cast<uint32_t>(
                   send_async_data.overlapped->internal_high));
        break;
      default:
        send_async_data.overlapped->internal_high = 0;
        ret = 0;
        break;
    }
  } else {
    send_async_data.overlapped->internal_high = 0;
    send_async_data.overlapped->internal = bytes_sent;
  }

  send_async_data.overlapped->offset = flags;
#else
  // Linux legacy path could use sendmsg(); omitted here.
  ret = -1;
  send_async_data.overlapped->internal_high =
      (uint32_t)X_WSAError::X_WSAEWOULDBLOCK;
#endif

  delete[] buffers;

threadexit:
  if (wait) {
    delete[] send_async_data.buffers;
  }

  send_async_data.overlapped->offset_high |= WSAInfo::complete;

  if (wait && send_async_data.overlapped->event_handle) {
    xboxkrnl::xeNtSetEvent(send_async_data.overlapped->event_handle, nullptr);
  }

  send_cv_.notify_all();
  return ret;
}

int XSocket::WSARecvFrom(XWSABUF* buffers, uint32_t num_buffers,
                         xe::be<uint32_t>* num_bytes_recv_ptr,
                         xe::be<uint32_t>* flags_ptr, XSOCKADDR_IN* from_ptr,
                         xe::be<uint32_t>* fromlen_ptr,
                         XWSAOVERLAPPED* overlapped_ptr) {
  if (!buffers || !flags_ptr || (from_ptr && !fromlen_ptr)) {
    SetLastWSAError(X_WSAError::X_WSA_INVALID_PARAMETER);
    return -1;
  }

  // FSM-first: try to satisfy from recv ring immediately.
  uint32_t total_cap = 0;
  for (uint32_t i = 0; i < num_buffers; ++i) total_cap += buffers[i].len;

  sockaddr sa{};
  int salen = sizeof(sockaddr);
  uint8_t* first_buf =
      reinterpret_cast<uint8_t*>(
          kernel_state()->memory()->TranslateVirtual(buffers[0].buf_ptr));
  uint32_t got = 0;

  if (TryDequeueRecv_(first_buf, buffers[0].len, &got,
                      from_ptr ? &sa : nullptr, from_ptr ? &salen : nullptr)) {
    // Copy into multiple buffers if needed.
    if (got > buffers[0].len) {
      uint32_t off = buffers[0].len;
      for (uint32_t i = 1; i < num_buffers && off < got; ++i) {
        uint8_t* dst = reinterpret_cast<uint8_t*>(
            kernel_state()->memory()->TranslateVirtual(buffers[i].buf_ptr));
        uint32_t n = std::min<uint32_t>(buffers[i].len, got - off);
        std::memcpy(dst, first_buf + off, n);
        off += n;
      }
    }

    if (from_ptr) {
      from_ptr->to_guest(&sa);
      if (fromlen_ptr) *fromlen_ptr = salen;
    }

    if (num_bytes_recv_ptr) *num_bytes_recv_ptr = got;
    if (overlapped_ptr) {
      overlapped_ptr->internal = got;
      overlapped_ptr->internal_high = 0;
      overlapped_ptr->offset_high |= WSAInfo::complete;
      overlapped_ptr->offset = *flags_ptr;
      if (overlapped_ptr->event_handle) {
        xboxkrnl::xeNtSetEvent(overlapped_ptr->event_handle, nullptr);
      }
    }
    SetLastWSAError((X_WSAError)0);
    return 0;  // immediate success
  }

  // ===== Legacy poll path (only when ring has nothing) =====
  WSARecvFromData receive_async_data = {};
  receive_async_data.buffers = buffers;
  receive_async_data.num_buffers = num_buffers;
  receive_async_data.flags = *flags_ptr;
  receive_async_data.from = from_ptr;
  receive_async_data.from_len = fromlen_ptr;

  XWSAOVERLAPPED tmp_overlapped;
  std::memset(&tmp_overlapped, 0, sizeof(tmp_overlapped));

  if (overlapped_ptr) {
    overlapped_ptr->offset_high |= WSAInfo::recvfrom_flag;
  }

  receive_async_data.overlapped =
      overlapped_ptr ? overlapped_ptr : &tmp_overlapped;

  int ret = PollWSARecvFrom(false, receive_async_data);

  if (ret < 0) {
    auto wsa_error = receive_async_data.overlapped->internal_high.get();
    SetLastWSAError((X_WSAError)wsa_error);

    if (overlapped_ptr &&
        wsa_error == (uint32_t)X_WSAError::X_WSAEWOULDBLOCK) {
      std::lock_guard<std::mutex> lk(receive_mutex_);

      if (!receive_active_overlapped_ ||
          (receive_active_overlapped_->offset_high & WSAInfo::complete)) {
        // Copy stack args
        receive_async_data.buffers = new XWSABUF[num_buffers];
        std::memcpy(receive_async_data.buffers, buffers,
                    num_buffers * sizeof(XWSABUF));

        overlapped_ptr->offset_high |= WSAInfo::recvfrom_flag;

        if (overlapped_ptr->event_handle) {
          xboxkrnl::xeNtClearEvent(overlapped_ptr->event_handle);
        }
        receive_active_overlapped_ = overlapped_ptr;

        if (!polling_task_.valid()) {
          polling_task_ =
              std::async(std::launch::async, &XSocket::PollWSARecvFrom, this,
                         true, receive_async_data);
        } else {
          auto status = polling_task_.wait_for(0ms);
          if (status == std::future_status::ready) {
            (void)polling_task_.get();
          }
        }
        SetLastWSAError(X_WSAError::X_WSA_IO_PENDING);
      }
    }
  } else {
    if (num_bytes_recv_ptr) {
      *num_bytes_recv_ptr = receive_async_data.overlapped->internal;
    }
    *flags_ptr = receive_async_data.overlapped->offset;
  }

  if (receive_async_data.overlapped->internal_high.get() != 0)
    return ret;
  else if (ret >= 0)
    return ret;
  else
    return 0;
}

int XSocket::PollWSARecvFrom(bool wait, WSARecvFromData receive_async_data) {
  receive_async_data.overlapped->internal_high = 0;

  WSAPOLLFD fds = {};
  fds.fd = native_handle_;
  fds.events = POLLIN;

  DWORD bytes_received = 0;
  DWORD flags = receive_async_data.flags;
  auto buffers = new WSABUF[receive_async_data.num_buffers];

  sockaddr* sa = nullptr;
  if (receive_async_data.from) {
    sockaddr addr = receive_async_data.from->to_host();
    sa = const_cast<sockaddr*>(&addr);
  }

  int ret;
  do {
#ifdef XE_PLATFORM_WIN32
    ret = WSAPoll(&fds, 1, wait ? 1000 : 0);
#else
    ret = poll(&fds, 1, wait ? 1000 : 0);
#endif

    if (receive_async_data.overlapped->offset_high & WSAInfo::closed) {
      receive_async_data.overlapped->internal_high =
          (uint32_t)X_WSAError::X_WSA_OPERATION_ABORTED;
      ret = -1;
      goto threadexit;
    }
  } while (ret == 0 && wait);

  if (ret < 0) {
    receive_async_data.overlapped->internal_high = GetLastWSAError();
    XELOGE("XSocket receive thread failed polling with error {}",
           static_cast<uint32_t>(receive_async_data.overlapped->internal_high));
    goto threadexit;
  }

#ifdef XE_PLATFORM_WIN32
  for (auto i = 0u; i < receive_async_data.num_buffers; i++) {
    buffers[i].len = receive_async_data.buffers[i].len;
    buffers[i].buf =
        reinterpret_cast<CHAR*>(kernel_state()->memory()->TranslateVirtual(
            receive_async_data.buffers[i].buf_ptr));
  }

  ret = ::WSARecvFrom(native_handle_, buffers, receive_async_data.num_buffers,
                      &bytes_received, &flags, sa,
                      (LPINT)receive_async_data.from_len, nullptr, nullptr);
  if (ret < 0) {
    receive_async_data.overlapped->internal_high = GetLastWSAError();

    switch (receive_async_data.overlapped->internal_high) {
      case WSAEMSGSIZE:
      case WSAENETDOWN:
      case WSAEHOSTDOWN:
      case WSAEHOSTUNREACH:
      case WSAENETRESET:
      case WSAECONNABORTED:
      case WSAECONNRESET:
      case WSAENOTCONN:
      case WSAESHUTDOWN:
      case WSAETIMEDOUT:
        XELOGI("WSARecvFrom failed with UDP-specific error {}",
               static_cast<uint32_t>(
                   receive_async_data.overlapped->internal_high));
        break;
      default:
        receive_async_data.overlapped->internal_high = 0;
        ret = 0;
        break;
    }
  } else {
    receive_async_data.overlapped->internal_high = 0;
    receive_async_data.overlapped->internal = bytes_received;
  }
  if (receive_async_data.from && sa) {
    receive_async_data.from->to_guest(sa);
  }

  receive_async_data.overlapped->offset = flags;
#else
  // POSIX path would use recvmsg(); omitted.
  ret = -1;
  receive_async_data.overlapped->internal_high =
      (uint32_t)X_WSAError::X_WSAEWOULDBLOCK;
#endif

  delete[] buffers;

threadexit:
  if (wait) {
    delete[] receive_async_data.buffers;
  }

  receive_async_data.overlapped->offset_high |= WSAInfo::complete;

  if (wait && receive_async_data.overlapped->event_handle) {
    xboxkrnl::xeNtSetEvent(receive_async_data.overlapped->event_handle,
                           nullptr);
  }

  receive_cv_.notify_all();

  return ret;
}

bool XSocket::WSAGetOverlappedResult(XWSAOVERLAPPED* overlapped_ptr,
                                     xe::be<uint32_t>* bytes_transferred,
                                     bool wait, xe::be<uint32_t>* flags_ptr) {
  if (!overlapped_ptr || !bytes_transferred || !flags_ptr) {
    SetLastWSAError(X_WSAError::X_WSA_INVALID_PARAMETER);
    return false;
  }

  if (overlapped_ptr->offset_high & WSAInfo::sendto_flag) {
    std::unique_lock lock(send_mutex_);

    if (!(overlapped_ptr->offset_high & WSAInfo::complete) ||
        overlapped_ptr->internal_high ==
            (uint32_t)X_WSAError::X_WSAEWOULDBLOCK) {
      if (wait) {
        send_cv_.wait(lock);
      } else {
        SetLastWSAError(X_WSAError::X_WSA_IO_INCOMPLETE);
        return false;
      }
    }

    *bytes_transferred = overlapped_ptr->internal;
    *flags_ptr = overlapped_ptr->offset;

    send_active_overlapped_ = nullptr;
  }

  if (overlapped_ptr->offset_high & WSAInfo::recvfrom_flag) {
    std::unique_lock lock(receive_mutex_);

    if (!(overlapped_ptr->offset_high & WSAInfo::complete) ||
        overlapped_ptr->internal_high ==
            (uint32_t)X_WSAError::X_WSAEWOULDBLOCK) {
      if (wait) {
        receive_cv_.wait(lock);
      } else {
        SetLastWSAError(X_WSAError::X_WSA_IO_INCOMPLETE);
        return false;
      }
    }

    *bytes_transferred = overlapped_ptr->internal;
    *flags_ptr = overlapped_ptr->offset;

    receive_active_overlapped_ = nullptr;
  }

  return true;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len,
              flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags,
                    XSOCKADDR_IN* to, uint32_t to_len) {
  to->address_port =
      XLiveAPI::upnp_handler->GetMappedBindPort(to->address_port);

  sockaddr addr = to->to_host();

  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                to ? &addr : nullptr, to_len);
}

int XSocket::WSAEventSelect(uint64_t socket_handle, uint64_t event_handle,
                            uint32_t flags) {
  return ::WSAEventSelect(socket_handle, reinterpret_cast<HANDLE>(event_handle),
                          flags);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port,
                          const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

X_STATUS XSocket::GetPeerName(XSOCKADDR_IN* buf, int* buf_len) {
  sockaddr addr = buf->to_host();
  sockaddr* sa = const_cast<sockaddr*>(&addr);

  int ret = getpeername(native_handle_, sa, (socklen_t*)buf_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  buf->to_guest(sa);
  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::GetSockName(XSOCKADDR_IN* buf, int* buf_len) {
  sockaddr addr = buf->to_host();
  sockaddr* sa = const_cast<sockaddr*>(&addr);

  int ret = getsockname(native_handle_, sa, (socklen_t*)buf_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  buf->to_guest(sa);
  return X_STATUS_SUCCESS;
}

uint32_t XSocket::GetLastWSAError() const {
#ifdef XE_PLATFORM_WIN32
  return WSAGetLastError();
#endif
  return errno;
}

void XSocket::SetLastWSAError(X_WSAError error) const {
#ifdef XE_PLATFORM_WIN32
  WSASetLastError((int)error);
#endif
  errno = (int)error;
}

}  // namespace kernel
}  // namespace xe
