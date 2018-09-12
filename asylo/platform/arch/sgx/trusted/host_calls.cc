/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// If the function invoked on the host sets the value of host errno, the new
// value is propagated back into the enclave. In this case, the value of errno
// in the enclave will reflect the error set by the host. Otherwise, the value
// of enclave errno is not altered.

#include "asylo/platform/arch/include/trusted/host_calls.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utime.h>
#include <cstring>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "asylo/platform/arch/include/trusted/memory.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/arch/sgx/trusted/generated_bridge_t.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_proto_serializer.h"
#include "asylo/platform/common/bridge_types.h"
#include "include/sgx_trts.h"

namespace asylo {
namespace {

// Allocates untrusted memory and copies the buffer |data| of size |size| to it.
// |addr| is updated to point to the address of the copied memory. It is the
// responsibility of the caller to free the memory pointed to by |addr|.
bool CopyToUntrustedMemory(void **addr, void *data, size_t size) {
  if (data && !addr) {
    return false;
  }
  // The operation trivially succeeds if there is nothing to copy.
  if (!data) {
    return true;
  }
  void *outside_enclave = enc_untrusted_malloc(size);
  memcpy(outside_enclave, data, size);
  *addr = outside_enclave;
  return true;
}

// This helper class wraps a bridge_msghdr and does a deep copy of all the
// buffers to untrusted memory.
class BridgeMsghdrWrapper {
 public:
  BridgeMsghdrWrapper(const struct msghdr *in);
  bridge_msghdr *get_msg();
  bool CopyAllBuffers();

 private:
  bool CopyMsgName();
  bool CopyMsgIov();
  bool CopyMsgIovBase();
  bool CopyMsgControl();

  const msghdr *msg_in_;
  UntrustedUniquePtr<bridge_msghdr> msg_out_;
  UntrustedUniquePtr<void> msg_name_ptr_;
  UntrustedUniquePtr<void> msg_iov_ptr_;
  UntrustedUniquePtr<void> msg_control_ptr_;
  std::vector<UntrustedUniquePtr<void>> msg_iov_base_ptrs_;
};

BridgeMsghdrWrapper::BridgeMsghdrWrapper(const struct msghdr *in) {
  struct bridge_msghdr tmp;
  ToBridgeMsgHdr(in, &tmp);
  struct bridge_msghdr *tmp_bridge_msghdr(nullptr);
  bool ret =
      CopyToUntrustedMemory(reinterpret_cast<void **>(&tmp_bridge_msghdr), &tmp,
                            sizeof(struct bridge_msghdr));
  if (ret && tmp_bridge_msghdr) {
    msg_out_.reset(tmp_bridge_msghdr);
  }
  msg_in_ = in;
}

bridge_msghdr *BridgeMsghdrWrapper::get_msg() { return msg_out_.get(); }

bool BridgeMsghdrWrapper::CopyMsgName() {
  void *tmp_name_ptr(nullptr);
  if (!CopyToUntrustedMemory(&tmp_name_ptr, msg_in_->msg_name,
                             msg_in_->msg_namelen)) {
    return false;
  }
  if (tmp_name_ptr) {
    msg_name_ptr_.reset(tmp_name_ptr);
    msg_out_->msg_name = tmp_name_ptr;
  }
  return true;
}

bool BridgeMsghdrWrapper::CopyMsgIov() {
  struct bridge_iovec *tmp_iov_ptr = reinterpret_cast<struct bridge_iovec *>(
      enc_untrusted_malloc(msg_in_->msg_iovlen * sizeof(struct bridge_iovec)));
  if (tmp_iov_ptr) {
    msg_iov_ptr_.reset(tmp_iov_ptr);
    msg_out_->msg_iov = tmp_iov_ptr;
  }
  for (int i = 0; i < msg_in_->msg_iovlen; ++i) {
    if (!ToBridgeIovec(&msg_in_->msg_iov[i], &msg_out_->msg_iov[i])) {
      return false;
    }
  }
  return true;
}

bool BridgeMsghdrWrapper::CopyMsgIovBase() {
  for (int i = 0; i < msg_in_->msg_iovlen; ++i) {
    msg_iov_base_ptrs_.push_back(nullptr);
    void *tmp_iov_base_ptr(nullptr);
    if (!CopyToUntrustedMemory(&tmp_iov_base_ptr, msg_in_->msg_iov[i].iov_base,
                               msg_in_->msg_iov[i].iov_len)) {
      return false;
    }
    if (tmp_iov_base_ptr) {
      msg_iov_base_ptrs_[i].reset(tmp_iov_base_ptr);
      msg_out_->msg_iov[i].iov_base = tmp_iov_base_ptr;
    }
  }
  return true;
}

bool BridgeMsghdrWrapper::CopyMsgControl() {
  void *tmp_control_ptr(nullptr);
  if (!CopyToUntrustedMemory(&tmp_control_ptr, msg_in_->msg_control,
                             msg_in_->msg_controllen)) {
    return false;
  }
  if (tmp_control_ptr) {
    msg_control_ptr_.reset(tmp_control_ptr);
    msg_out_->msg_control = tmp_control_ptr;
  }
  return true;
}

bool BridgeMsghdrWrapper::CopyAllBuffers() {
  if (!CopyMsgName() || !CopyMsgIov() || !CopyMsgIovBase() ||
      !CopyMsgControl()) {
    return false;
  }
  return true;
}

}  // namespace
}  // namespace asylo

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////
//              IO                   //
///////////////////////////////////////

void *enc_untrusted_malloc(size_t size) {
  void *result;
  sgx_status_t status =
      ocall_enc_untrusted_malloc(&result, static_cast<bridge_size_t>(size));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    abort();
  }
  if (result &&
      !sgx_is_outside_enclave(result, static_cast<bridge_size_t>(size))) {
    abort();
  }
  if (!result) {
    abort();
  }
  return result;
}

int enc_untrusted_open(const char *path_name, int flags, ...) {
  uint32_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }

  int bridge_flags = asylo::ToBridgeFileFlags(flags);
  int result;
  sgx_status_t status =
      ocall_enc_untrusted_open(&result, path_name, bridge_flags, mode);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return result;
}

int enc_untrusted_puts(const char *str) {
  int result;
  sgx_status_t status = ocall_enc_untrusted_puts(&result, str);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return EOF;
  }
  return result;
}

int FcntlHelper(int fd, int cmd, int64_t arg) {
  int result;
  sgx_status_t status = ocall_enc_untrusted_fcntl(&result, fd, cmd, arg);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return result;
}

int enc_untrusted_fcntl(int fd, int cmd, ...) {
  int64_t arg = 0;
  va_list ap;
  va_start(ap, cmd);
  arg = va_arg(ap, int64_t);
  va_end(ap);

  switch (cmd) {
    case F_SETFL: {
      arg = asylo::ToBridgeFileFlags(arg);
      return FcntlHelper(fd, cmd, arg);
    }
    case F_SETFD: {
      arg = asylo::ToBridgeFDFlags(arg);
      return FcntlHelper(fd, cmd, arg);
    }
    case F_GETFL: {
      int result = FcntlHelper(fd, cmd, arg);
      if (result != -1) {
        result = asylo::FromBridgeFileFlags(result);
      }
      return result;
    }
    case F_GETFD: {
      int result = FcntlHelper(fd, cmd, arg);
      if (result != -1) {
        result = asylo::FromBridgeFDFlags(result);
      }
      return result;
    }
    default: {
      errno = EINVAL;
      return -1;
    }
  }
}

int enc_untrusted_stat(const char *pathname, struct stat *stat_buffer) {
  int result;
  struct bridge_stat bridge_stat_buffer;
  sgx_status_t status =
      ocall_enc_untrusted_stat(&result, pathname, &bridge_stat_buffer);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeStat(&bridge_stat_buffer, stat_buffer);
  return result;
}

int enc_untrusted_fstat(int fd, struct stat *stat_buffer) {
  int result;
  struct bridge_stat bridge_stat_buffer;
  sgx_status_t status =
      ocall_enc_untrusted_fstat(&result, fd, &bridge_stat_buffer);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeStat(&bridge_stat_buffer, stat_buffer);
  return result;
}

int enc_untrusted_lstat(const char *pathname, struct stat *stat_buffer) {
  int result;
  struct bridge_stat bridge_stat_buffer;
  sgx_status_t status =
      ocall_enc_untrusted_lstat(&result, pathname, &bridge_stat_buffer);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeStat(&bridge_stat_buffer, stat_buffer);
  return result;
}

bool create_untrusted_buffer(const struct iovec *iov, int iovcnt, char **buf,
                             int *size) {
  int tmp_size = 0;
  for (int i = 0; i < iovcnt; ++i) {
    tmp_size += iov[i].iov_len;
  }
  char *tmp =
      reinterpret_cast<char *>(enc_untrusted_malloc(tmp_size * sizeof(char)));
  if (!tmp) {
    return false;
  }
  *size = tmp_size;
  *buf = tmp;
  return true;
}

bool serialize_iov(const struct iovec *iov, int iovcnt, char **buf, int *size) {
  char *tmp;
  if (!create_untrusted_buffer(iov, iovcnt, &tmp, size)) {
    return false;
  }
  int copied_bytes = 0;
  for (int i = 0; i < iovcnt; ++i) {
    memcpy(tmp + copied_bytes, iov[i].iov_base, iov[i].iov_len);
    copied_bytes += iov[i].iov_len;
  }
  *buf = tmp;
  return true;
}

void fill_iov(const char *buf, int size, const struct iovec *iov, int iovcnt) {
  size_t bytes_left = size;
  for (int i = 0; i < iovcnt; ++i) {
    if (bytes_left == 0) {
      break;
    }
    int bytes_to_copy = std::min(bytes_left, iov[i].iov_len);
    memcpy(iov[i].iov_base, buf, bytes_to_copy);
    buf += bytes_to_copy;
    bytes_left -= bytes_to_copy;
  }
}

ssize_t enc_untrusted_writev(int fd, const struct iovec *iov, int iovcnt) {
  if (iovcnt <= 0) {
    errno = EINVAL;
    return -1;
  }

  char *buf;
  int size;
  if (!serialize_iov(iov, iovcnt, &buf, &size)) {
    return -1;
  }
  asylo::UntrustedUniquePtr<char> tmp(buf);
  bridge_ssize_t ret;

  sgx_status_t status =
      ocall_enc_untrusted_write_with_untrusted_ptr(&ret, fd, buf, size);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return static_cast<ssize_t>(ret);
}

ssize_t enc_untrusted_readv(int fd, const struct iovec *iov, int iovcnt) {
  if (iovcnt <= 0) {
    errno = EINVAL;
    return -1;
  }
  char *buf;
  int size;
  if (!create_untrusted_buffer(iov, iovcnt, &buf, &size)) {
    return -1;
  }

  asylo::UntrustedUniquePtr<char> tmp(buf);
  bridge_ssize_t ret;
  sgx_status_t status =
      ocall_enc_untrusted_read_with_untrusted_ptr(&ret, fd, buf, size);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  fill_iov(buf, ret, iov, iovcnt);
  return static_cast<ssize_t>(ret);
}

//////////////////////////////////////
//             Sockets              //
//////////////////////////////////////

int enc_untrusted_accept(int sockfd, struct sockaddr *addr,
                         socklen_t *addrlen) {
  int ret;
  struct bridge_sockaddr tmp;
  sgx_status_t status = ocall_enc_untrusted_accept(&ret, sockfd, &tmp);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  if (ret == -1) {
    return ret;
  }
  if (addr && addrlen) {
    asylo::FromBridgeSockaddr(&tmp, addr, addrlen);
  }
  return ret;
}

int enc_untrusted_bind(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {
  int ret;
  struct bridge_sockaddr tmp;
  sgx_status_t status = ocall_enc_untrusted_bind(
      &ret, sockfd, asylo::ToBridgeSockaddr(addr, addrlen, &tmp));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_connect(int sockfd, const struct sockaddr *addr,
                          socklen_t addrlen) {
  int ret;
  struct bridge_sockaddr tmp;
  sgx_status_t status = ocall_enc_untrusted_connect(
      &ret, sockfd, asylo::ToBridgeSockaddr(addr, addrlen, &tmp));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

ssize_t enc_untrusted_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  bridge_ssize_t ret;
  asylo::BridgeMsghdrWrapper tmp_wrapper(msg);
  if (!tmp_wrapper.CopyAllBuffers()) {
    errno = EFAULT;
    return -1;
  }

  sgx_status_t status =
      ocall_enc_untrusted_sendmsg(&ret, sockfd, tmp_wrapper.get_msg(), flags);

  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return static_cast<ssize_t>(ret);
}

ssize_t enc_untrusted_recvmsg(int sockfd, struct msghdr *msg, int flags) {
  bridge_ssize_t ret;
  asylo::BridgeMsghdrWrapper tmp_wrapper(msg);
  if (!tmp_wrapper.CopyAllBuffers()) {
    errno = EFAULT;
    return -1;
  }

  sgx_status_t status =
      ocall_enc_untrusted_recvmsg(&ret, sockfd, tmp_wrapper.get_msg(), flags);

  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }

  asylo::FromBridgeIovecArray(tmp_wrapper.get_msg(), msg);
  return static_cast<ssize_t>(ret);
}

const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size) {
  char *ret;
  bridge_size_t src_size;
  if (af == AF_INET) {
    src_size = static_cast<bridge_size_t>(sizeof(struct in_addr));
  } else if (af == AF_INET6) {
    src_size = static_cast<bridge_size_t>(sizeof(struct in6_addr));
  } else {
    errno = EAFNOSUPPORT;
    return nullptr;
  }
  sgx_status_t status = ocall_enc_untrusted_inet_ntop(
      &ret, af, src, src_size, dst, static_cast<bridge_size_t>(size));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return nullptr;
  }
  // Instead of returning |ret| (which points to untrusted memory), we return
  // |dst| upon success (when |ret| is non-null) and nullptr upon failure.
  if (!ret) {
    return nullptr;
  }
  return dst;
}

int enc_untrusted_inet_pton(int af, const char *src, void *dst) {
  int ret = 0;
  bridge_size_t dst_size = 0;
  if (af == AF_INET) {
    dst_size = static_cast<bridge_size_t>(sizeof(struct in_addr));
  } else if (af == AF_INET6) {
    dst_size = static_cast<bridge_size_t>(sizeof(struct in6_addr));
  } else {
    errno = EINVAL;
    return -1;
  }
  sgx_status_t status = ocall_enc_untrusted_inet_pton(
      &ret, asylo::ToBridgeAfFamily(af), src, dst, dst_size);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return 0;
  }
  return ret;
}

int enc_untrusted_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res) {
  std::string serialized_hints;
  struct addrinfo bridge_hints;
  if (hints) {
    bridge_hints = *hints;
    bridge_hints.ai_flags =
        asylo::ToBridgeAddressInfoFlags(bridge_hints.ai_flags);
  }
  // Serialize an empty addrinfo if |hints| is nullptr.
  if (!asylo::SerializeAddrinfo(hints ? &bridge_hints : nullptr,
                                &serialized_hints)) {
    return -1;
  }

  int ret;
  char *tmp_serialized_res_start;
  bridge_size_t tmp_serialized_res_len;
  sgx_status_t status = ocall_enc_untrusted_getaddrinfo(
      &ret, node, service, serialized_hints.c_str(),
      static_cast<bridge_size_t>(serialized_hints.length()),
      &tmp_serialized_res_start, &tmp_serialized_res_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  } else if (ret != 0) {
    return ret;
  } else if (!sgx_is_outside_enclave(
                 tmp_serialized_res_start,
                 static_cast<size_t>(tmp_serialized_res_len))) {
    return -1;
  }

  // Copy then free serialized res from untrusted memory
  char tmp_serialized_res[tmp_serialized_res_len];
  memcpy(tmp_serialized_res, tmp_serialized_res_start,
         static_cast<size_t>(tmp_serialized_res_len));
  enc_untrusted_free(tmp_serialized_res_start);

  std::string serialized_res(tmp_serialized_res,
                        static_cast<size_t>(tmp_serialized_res_len));
  if (!asylo::DeserializeAddrinfo(&serialized_res, res)) return -1;
  return ret;
}

void enc_untrusted_freeaddrinfo(struct addrinfo *res) {
  asylo::FreeDeserializedAddrinfo(res);
}

int enc_untrusted_getsockopt(int sockfd, int level, int optname, void *optval,
                             socklen_t *optlen) {
  int ret;
  unsigned int host_optlen = *optlen;
  sgx_status_t status = ocall_enc_untrusted_getsockopt(
      &ret, sockfd, level, asylo::ToBridgeOptionName(level, optname), optval,
      host_optlen, &host_optlen);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  *optlen = host_optlen;
  return ret;
}

int enc_untrusted_setsockopt(int sockfd, int level, int optname,
                             const void *optval, socklen_t optlen) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_setsockopt(
      &ret, sockfd, level, asylo::FromBridgeOptionName(level, optname), optval,
      static_cast<bridge_size_t>(optlen));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_getsockname(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen) {
  int ret;
  struct bridge_sockaddr tmp;
  sgx_status_t status =
      ocall_enc_untrusted_getsockname(&ret, sockfd, &tmp);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeSockaddr(&tmp, addr, addrlen);
  return ret;
}

int enc_untrusted_getpeername(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen) {
  int ret;
  struct bridge_sockaddr tmp;
  sgx_status_t status =
      ocall_enc_untrusted_getpeername(&ret, sockfd, &tmp);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeSockaddr(&tmp, addr, addrlen);
  return ret;
}

ssize_t enc_untrusted_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen) {
  ssize_t ret = 0;
  char *serialized_args = nullptr;
  size_t serialized_len = 0;
  if (!asylo::SerializeRecvFromArgs(sockfd, len, flags, &serialized_args,
                                    &serialized_len)) {
    errno = EINVAL;
    return -1;
  }
  asylo::MallocUniquePtr<char[]> args_ptr(serialized_args);
  char *serialized_output = nullptr;
  char **serialized_output_ptr = src_addr ? &serialized_output : nullptr;
  char *output_buf = nullptr;
  bridge_ssize_t output_len = 0;
  sgx_status_t status = ocall_enc_untrusted_recvfrom(
      &ret, serialized_args, serialized_len, &output_buf, serialized_output_ptr,
      &output_len);
  asylo::UntrustedUniquePtr<char[]> output_buf_ptr(output_buf);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  if (ret < 0) {
    // errno is propagated.
    return -1;
  }
  if (!sgx_is_outside_enclave(output_buf, ret)) {
    abort();
  }
  memcpy(buf, output_buf, ret);
  if (src_addr) {
    struct sockaddr *src_addr_copy = nullptr;
    asylo::UntrustedUniquePtr<char[]> output_unique_ptr(serialized_output);
    if (!sgx_is_outside_enclave(serialized_output, output_len)) {
      abort();
    }
    std::string serialized_output_str(serialized_output, output_len);
    if (!addrlen || !asylo::DeserializeRecvFromSrcAddr(serialized_output_str,
                                                       &src_addr_copy)) {
      errno = EINVAL;
      return -1;
    }
    asylo::MallocUniquePtr<struct sockaddr> src_addr_ptr(src_addr_copy);
    if (src_addr_copy->sa_family == AF_INET) {
      memcpy(
          src_addr, src_addr_copy,
          std::min(static_cast<size_t>(*addrlen), sizeof(struct sockaddr_in)));
      *addrlen = sizeof(struct sockaddr_in);
    } else if (src_addr_copy->sa_family == AF_INET6) {
      memcpy(
          src_addr, src_addr_copy,
          std::min(static_cast<size_t>(*addrlen), sizeof(struct sockaddr_in6)));
      *addrlen = sizeof(struct sockaddr_in6);
    } else {
      errno = EINVAL;
      return -1;
    }
  }
  return ret;
}

//////////////////////////////////////
//           Threading              //
//////////////////////////////////////

int enc_untrusted_create_thread(const char *name) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_thread_create(&ret, name);
  if (status != SGX_SUCCESS) {
    return -1;
  }

  return 0;
}

//////////////////////////////////////
//           poll.h                 //
//////////////////////////////////////

int enc_untrusted_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  int ret;
  auto tmp = absl::make_unique<bridge_pollfd[]>(nfds);
  for (int i = 0; i < nfds; ++i) {
    if (!asylo::ToBridgePollfd(&fds[i], &tmp[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  sgx_status_t status =
      ocall_enc_untrusted_poll(&ret, tmp.get(), nfds, timeout);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  for (int i = 0; i < nfds; ++i) {
    if (!asylo::FromBridgePollfd(&tmp[i], &fds[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  return ret;
}

//////////////////////////////////////
//           epoll.h                //
//////////////////////////////////////

int enc_untrusted_epoll_create(int size) {
  int ret = 0;
  sgx_status_t status = ocall_enc_untrusted_epoll_create(&ret, size);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_epoll_ctl(int epfd, int op, int fd,
                            struct epoll_event *event) {
  char *serialized_args = nullptr;
  asylo::MallocUniquePtr<char[]> args_ptr(serialized_args);
  size_t len = 0;
  if (!asylo::SerializeEpollCtlArgs(epfd, op, fd, event, &serialized_args,
                                    &len)) {
    errno = EINVAL;
    return -1;
  }
  bridge_size_t serialized_args_len = static_cast<bridge_size_t>(len);
  int ret = 0;
  sgx_status_t status =
      ocall_enc_untrusted_epoll_ctl(&ret, serialized_args, serialized_args_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_epoll_wait(int epfd, struct epoll_event *events,
                             int maxevents, int timeout) {
  char *serialized_args = nullptr;
  asylo::MallocUniquePtr<char[]> args_ptr(serialized_args);
  size_t len = 0;
  if (!asylo::SerializeEpollWaitArgs(epfd, maxevents, timeout, &serialized_args,
                                     &len)) {
    errno = EINVAL;
    return -1;
  }

  bridge_size_t serialized_args_len = static_cast<bridge_size_t>(len);
  int ret = 0;
  char *serialized_event_list = nullptr;
  bridge_size_t serialized_event_list_len = 0;
  sgx_status_t status = ocall_enc_untrusted_epoll_wait(
      &ret, serialized_args, serialized_args_len, &serialized_event_list,
      &serialized_event_list_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  if (!sgx_is_outside_enclave(serialized_event_list,
                              serialized_event_list_len)) {
    abort();
  }
  asylo::UntrustedUniquePtr<char[]>
      serialized_events_ptr(serialized_event_list);
  // The line below intentially copies |serialized_event_list| into trusted
  // memory.
  std::string event_list_str(serialized_event_list, serialized_event_list_len);
  int numevents = 0;
  if (!asylo::DeserializeEvents(event_list_str, events, &numevents)) {
    errno = EBADE;
    return -1;
  }
  // Check if the number of events in the deserialized results (|numevents|) is
  // the same as the return value of epoll_wait (|ret|). An inconsistency would
  // suggest malicious behavior, therefore, we would abort().
  if (numevents != ret) {
    abort();
  }
  return ret;
}

//////////////////////////////////////
//           inotify.h              //
//////////////////////////////////////

int enc_untrusted_inotify_init1(bool non_block) {
  int ret = 0;
  sgx_status_t status = ocall_enc_untrusted_inotify_init1(&ret, non_block);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_inotify_add_watch(int fd, const char *pathname,
                                    uint32_t mask) {
  char *serialized_args = nullptr;
  asylo::MallocUniquePtr<char> args_ptr(serialized_args);
  size_t len = 0;
  if (!asylo::SerializeInotifyAddWatchArgs(fd, pathname, mask, &serialized_args,
                                           &len)) {
    return -1;
  }
  bridge_size_t serialized_args_len = static_cast<bridge_size_t>(len);
  int ret = 0;
  sgx_status_t status = ocall_enc_untrusted_inotify_add_watch(
      &ret, serialized_args, serialized_args_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_inotify_rm_watch(int fd, int wd) {
  char *serialized_args = nullptr;
  asylo::MallocUniquePtr<char> args_ptr(serialized_args);
  size_t len = 0;
  if (!asylo::SerializeInotifyRmWatchArgs(fd, wd, &serialized_args, &len)) {
    errno = EINVAL;
    return -1;
  }
  bridge_size_t serialized_args_len = static_cast<bridge_size_t>(len);
  int ret = 0;
  sgx_status_t status = ocall_enc_untrusted_inotify_rm_watch(
      &ret, serialized_args, serialized_args_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_inotify_read(int fd, size_t count, char **serialized_events,
                               size_t *serialized_events_len) {
  int ret = 0;
  sgx_status_t status = ocall_enc_untrusted_inotify_read(
      &ret, fd, count, serialized_events, serialized_events_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//           ifaddrs.h              //
//////////////////////////////////////

int enc_untrusted_getifaddrs(struct ifaddrs **ifap) {
  char *serialized_ifaddrs = nullptr;
  bridge_ssize_t serialized_ifaddrs_len = 0;
  int ret = 0;
  int status = ocall_enc_untrusted_getifaddrs(&ret, &serialized_ifaddrs,
                                              &serialized_ifaddrs_len);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  if (ret != 0) {
    return ret;
  }
  if (!sgx_is_outside_enclave(serialized_ifaddrs,
                              static_cast<size_t>(serialized_ifaddrs_len))) {
    return -1;
  }
  asylo::UntrustedUniquePtr<char> ifaddrs_str_ptr(serialized_ifaddrs);
  std::string ifaddrs_str(serialized_ifaddrs, serialized_ifaddrs_len);
  if (!asylo::DeserializeIfAddrs(ifaddrs_str, ifap)) return -1;
  return ret;
}

void enc_untrusted_freeifaddrs(struct ifaddrs *ifa) {
  asylo::FreeDeserializedIfAddrs(ifa);
}

//////////////////////////////////////
//           sched.h                //
//////////////////////////////////////

int enc_untrusted_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                    cpu_set_t *mask) {
  if (cpusetsize < sizeof(cpu_set_t)) {
    errno = EINVAL;
    return -1;
  }

  int ret;
  BridgeCpuSet bridge_mask;
  sgx_status_t status = ocall_enc_untrusted_sched_getaffinity(
      &ret, static_cast<int64_t>(pid), &bridge_mask);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }

  // Translate from bridge_cpu_set_t to enclave cpu_set_t.
  CPU_ZERO(mask);
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (asylo::BridgeCpuSetCheckBit(cpu, &bridge_mask)) {
      CPU_SET(cpu, mask);
    }
  }

  return ret;
}

//////////////////////////////////////
//           signal.h               //
//////////////////////////////////////

int enc_untrusted_register_signal_handler(
    int signum, void (*bridge_sigaction)(int, bridge_siginfo_t *, void *),
    const sigset_t mask, const char *enclave_name) {
  int bridge_signum = asylo::ToBridgeSignal(signum);
  if (bridge_signum < 0) {
    errno = EINVAL;
    return -1;
  }
  BridgeSignalHandler handler;
  handler.sigaction = bridge_sigaction;
  asylo::ToBridgeSigSet(&mask, &handler.mask);
  int ret;
  sgx_status_t status = ocall_enc_untrusted_register_signal_handler(
      &ret, bridge_signum, &handler, enclave_name);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  bridge_sigset_t bridge_set;
  asylo::ToBridgeSigSet(set, &bridge_set);
  bridge_sigset_t bridge_old_set;
  int ret;
  sgx_status_t status = ocall_enc_untrusted_sigprocmask(
      &ret, asylo::ToBridgeSigMaskAction(how), &bridge_set, &bridge_old_set);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeSigSet(&bridge_old_set, oldset);
  return ret;
}

//////////////////////////////////////
//         sys/resource.h           //
//////////////////////////////////////

int enc_untrusted_getrusage(int who, struct rusage *usage) {
  int ret;
  BridgeRUsage bridge_usage;
  sgx_status_t status = ocall_enc_untrusted_getrusage(
      &ret, asylo::ToBridgeRUsageTarget(who), &bridge_usage);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeRUsage(&bridge_usage, usage);
  return ret;
}

//////////////////////////////////////
//           sys/file.h             //
//////////////////////////////////////

int enc_untrusted_flock(int fd, int operation) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_flock(
      &ret, fd, asylo::ToBridgeFLockOperation(operation));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//          sys/syslog.h            //
//////////////////////////////////////

void enc_untrusted_openlog(const char *ident, int option, int facility) {
  ocall_enc_untrusted_openlog(ident, asylo::ToBridgeSysLogOption(option),
                              asylo::ToBridgeSysLogFacility(facility));
}

void enc_untrusted_syslog(int priority, const char *message) {
  ocall_enc_untrusted_syslog(asylo::ToBridgeSysLogPriority(priority), message);
}

//////////////////////////////////////
//           time.h                 //
//////////////////////////////////////

int enc_untrusted_nanosleep(const struct timespec *req, struct timespec *rem) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_nanosleep(
      &ret, reinterpret_cast<const bridge_timespec *>(req),
      reinterpret_cast<bridge_timespec *>(rem));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_clock_gettime(
      &ret, static_cast<bridge_clockid_t>(clk_id),
      reinterpret_cast<bridge_timespec *>(tp));
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int enc_untrusted_setitimer(int which, const struct itimerval *new_value,
                            struct itimerval *old_value) {
  int ret;
  struct BridgeITimerVal bridge_new_value, bridge_old_value;
  if (!asylo::ToBridgeITimerVal(new_value, &bridge_new_value)) {
    errno = EFAULT;
    return -1;
  }
  sgx_status_t status =
      ocall_enc_untrusted_setitimer(&ret, asylo::ToBridgeTimerType(which),
                                    &bridge_new_value, &bridge_old_value);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  asylo::FromBridgeITimerVal(&bridge_old_value, old_value);
  return ret;
}

//////////////////////////////////////
//           sys/time.h             //
//////////////////////////////////////

int enc_untrusted_gettimeofday(struct timeval *tv, void *tz) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_gettimeofday(
      &ret, reinterpret_cast<bridge_timeval *>(tv), nullptr);
  if (status != SGX_SUCCESS) {
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//         sys/utsname.h            //
//////////////////////////////////////

int enc_untrusted_uname(struct utsname *utsname_val) {
  if (!utsname_val) {
    errno = EFAULT;
    return -1;
  }

  struct BridgeUtsName bridge_utsname_val;
  int ret;
  sgx_status_t status = ocall_enc_untrusted_uname(&ret, &bridge_utsname_val);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  } else if (ret != 0) {
    return ret;
  }

  if (!asylo::ConvertUtsName(bridge_utsname_val, utsname_val)) {
    errno = EINTR;
    return -1;
  }

  return ret;
}

//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

int enc_untrusted_pipe(int pipefd[2]) {
  int ret;
  sgx_status_t status = ocall_enc_untrusted_pipe(&ret, pipefd);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

int64_t enc_untrusted_sysconf(int name) {
  int64_t ret;
  enum SysconfConstants bridge_name = asylo::ToSysconfConstants(name);
  if (bridge_name == UNKNOWN) {
    errno = EINVAL;
    return -1;
  }
  sgx_status_t status = ocall_enc_untrusted_sysconf(&ret, bridge_name);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

uint32_t enc_untrusted_sleep(uint32_t seconds) {
  uint32_t ret;
  ocall_enc_untrusted_sleep(&ret, seconds);
  return ret;
}

//////////////////////////////////////
//             wait.h               //
//////////////////////////////////////

pid_t enc_untrusted_wait3(int *wstatus, int options, struct rusage *rusage) {
  pid_t ret;
  struct BridgeWStatus bridge_wstatus;
  BridgeRUsage bridge_rusage;
  sgx_status_t status = ocall_enc_untrusted_wait3(
      &ret, &bridge_wstatus, asylo::ToBridgeWaitOptions(options),
      &bridge_rusage);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  if (wstatus) {
    *wstatus = asylo::FromBridgeWStatus(bridge_wstatus);
  }
  asylo::FromBridgeRUsage(&bridge_rusage, rusage);
  return ret;
}

//////////////////////////////////////
//           utime.h                //
//////////////////////////////////////

int enc_untrusted_utime(const char *filename, const struct utimbuf *times) {
  int ret;
  struct bridge_utimbuf tmp_bridge_utimbuf;
  sgx_status_t status = ocall_enc_untrusted_utime(
      &ret, filename, asylo::ToBridgeUtimbuf(times, &tmp_bridge_utimbuf));
  if (status != SGX_SUCCESS) {
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//           Runtime support        //
//////////////////////////////////////

void *enc_untrusted_acquire_shared_resource(enum SharedNameKind kind,
                                            const char *name) {
  void *ret;
  sgx_status_t status =
      ocall_enc_untrusted_acquire_shared_resource(&ret, kind, name);
  if (status != SGX_SUCCESS) {
    return nullptr;
  }
  return ret;
}

int enc_untrusted_release_shared_resource(enum SharedNameKind kind,
                                          const char *name) {
  int ret;
  sgx_status_t status =
      ocall_enc_untrusted_release_shared_resource(&ret, kind, name);
  if (status != SGX_SUCCESS) {
    return -1;
  }
  return ret ? 0 : -1;
}

//////////////////////////////////////
//           Debugging              //
//////////////////////////////////////

void enc_untrusted_hex_dump(const void *buf, int nbytes) {
  ocall_enc_untrusted_hex_dump(buf, nbytes);
}

#ifdef __cplusplus
}  // extern "C"
#endif
