/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/platform/posix/io/native_paths.h"

#include <fcntl.h>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/posix/io/secure_paths.h"

namespace asylo {
namespace io {

int IOContextNative::Close() { return enc_untrusted_close(host_fd_); }

ssize_t IOContextNative::Read(void *buf, size_t count) {
  return enc_untrusted_read(host_fd_, buf, count);
}

ssize_t IOContextNative::Write(const void *buf, size_t count) {
  return enc_untrusted_write(host_fd_, buf, count);
}

int IOContextNative::LSeek(off_t offset, int whence) {
  return enc_untrusted_lseek(host_fd_, offset, whence);
}

int IOContextNative::FCntl(int cmd, int64_t arg) {
  return enc_untrusted_fcntl(host_fd_, cmd, arg);
}

int IOContextNative::FSync() { return enc_untrusted_fsync(host_fd_); }

int IOContextNative::FStat(struct stat *stat_buffer) {
  return enc_untrusted_fstat(host_fd_, stat_buffer);
}

int IOContextNative::FTruncate(off_t length) {
  return enc_untrusted_ftruncate(host_fd_, length);
}

int IOContextNative::Isatty() { return enc_untrusted_isatty(host_fd_); }

int IOContextNative::FLock(int operation) {
  return enc_untrusted_flock(host_fd_, operation);
}

ssize_t IOContextNative::Writev(const struct iovec *iov, int iovcnt) {
  return enc_untrusted_writev(host_fd_, iov, iovcnt);
}

ssize_t IOContextNative::Readv(const struct iovec *iov, int iovcnt) {
  return enc_untrusted_readv(host_fd_, iov, iovcnt);
}

int IOContextNative::SetSockOpt(int level, int option_name,
                                const void *option_value,
                                socklen_t option_len) {
  return enc_untrusted_setsockopt(host_fd_, level, option_name, option_value,
                                  option_len);
}

int IOContextNative::Connect(const struct sockaddr *addr, socklen_t addrlen) {
  return enc_untrusted_connect(host_fd_, addr, addrlen);
}

int IOContextNative::Shutdown(int how) {
  return enc_untrusted_shutdown(host_fd_, how);
}

ssize_t IOContextNative::Send(const void *buf, size_t len, int flags) {
  return enc_untrusted_send(host_fd_, buf, len, flags);
}

int IOContextNative::GetSockOpt(int level, int optname, void *optval,
                                socklen_t *optlen) {
  return enc_untrusted_getsockopt(host_fd_, level, optname, optval, optlen);
}

int IOContextNative::Accept(struct sockaddr *addr, socklen_t *addrlen) {
  return enc_untrusted_accept(host_fd_, addr, addrlen);
}

int IOContextNative::Bind(const struct sockaddr *addr, socklen_t addrlen) {
  return enc_untrusted_bind(host_fd_, addr, addrlen);
}

int IOContextNative::Listen(int backlog) {
  return enc_untrusted_listen(host_fd_, backlog);
}

ssize_t IOContextNative::SendMsg(const struct msghdr *msg, int flags) {
  return enc_untrusted_sendmsg(host_fd_, msg, flags);
}

ssize_t IOContextNative::RecvMsg(struct msghdr *msg, int flags) {
  return enc_untrusted_recvmsg(host_fd_, msg, flags);
}

int IOContextNative::GetSockName(struct sockaddr *addr, socklen_t *addrlen) {
  return enc_untrusted_getsockname(host_fd_, addr, addrlen);
}

int IOContextNative::GetPeerName(struct sockaddr *addr, socklen_t *addrlen) {
  return enc_untrusted_getpeername(host_fd_, addr, addrlen);
}

ssize_t IOContextNative::RecvFrom(void *buf, size_t len, int flags,
                                  struct sockaddr *src_addr,
                                  socklen_t *addrlen) {
  return enc_untrusted_recvfrom(host_fd_, buf, len, flags, src_addr, addrlen);
}

int IOContextNative::GetHostFileDescriptor() { return host_fd_; }

std::unique_ptr<IOManager::IOContext> NativePathHandler::Open(const char *path,
                                                              int flags,
                                                              mode_t mode) {
  if (flags & O_SECURE) {
    return IOContextSecure::Create(path, flags, mode);
  }

  int host_fd = enc_untrusted_open(path, flags, mode);
  if (host_fd < 0) {
    return nullptr;
  }

  return ::absl::make_unique<IOContextNative>(host_fd);
}

int NativePathHandler::Chown(const char *path, uid_t owner, gid_t group) {
  return enc_untrusted_chown(path, owner, group);
}

int NativePathHandler::Link(const char *existing, const char *new_link) {
  return enc_untrusted_link(existing, new_link);
}

int NativePathHandler::Unlink(const char *pathname) {
  return enc_untrusted_unlink(pathname);
}

ssize_t NativePathHandler::ReadLink(const char *path_name, char *buf,
                                    size_t bufsize) {
  return enc_untrusted_readlink(path_name, buf, bufsize);
}

int NativePathHandler::SymLink(const char *path1, const char *path2) {
  return enc_untrusted_symlink(path1, path2);
}

int NativePathHandler::Truncate(const char *path, off_t length) {
  return enc_untrusted_truncate(path, length);
}

int NativePathHandler::Stat(const char *pathname, struct stat *stat_buffer) {
  return enc_untrusted_stat(pathname, stat_buffer);
}

int NativePathHandler::LStat(const char *pathname, struct stat *stat_buffer) {
  return enc_untrusted_lstat(pathname, stat_buffer);
}

int NativePathHandler::Mkdir(const char *path, mode_t mode) {
  return enc_untrusted_mkdir(path, mode);
}

int NativePathHandler::Access(const char *path, int mode) {
  return enc_untrusted_access(path, mode);
}

int NativePathHandler::ChMod(const char *path, mode_t mode) {
  return enc_untrusted_chmod(path, mode);
}

}  // namespace io
}  // namespace asylo
