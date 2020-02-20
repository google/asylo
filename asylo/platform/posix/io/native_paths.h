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

#ifndef ASYLO_PLATFORM_POSIX_IO_NATIVE_PATHS_H_
#define ASYLO_PLATFORM_POSIX_IO_NATIVE_PATHS_H_

#include <utime.h>

#include "asylo/platform/posix/io/io_manager.h"

namespace asylo {
namespace io {

// IOContext implementation wrapping a host file descriptor, delegating IO
// operations to the host operating system.
class IOContextNative : public IOManager::IOContext {
 public:
  explicit IOContextNative(int host_fd) : host_fd_(host_fd) {}

  ssize_t Read(void *buf, size_t count) override;
  ssize_t Write(const void *buf, size_t count) override;
  int FChOwn(uid_t owner, gid_t group) override;
  int LSeek(off_t offset, int whence) override;
  int FCntl(int cmd, int64_t arg) override;
  int FSync() override;
  int FStat(struct stat *stat_buffer) override;
  int FStatFs(struct statfs *statfs_buffer) override;
  ssize_t FGetXattr(const char *name, void *value, size_t size) override;
  int FSetXattr(const char *name, const void *value, size_t size,
                int flags) override;
  ssize_t FListXattr(char *list, size_t size) override;
  int Isatty() override;
  int FLock(int operation) override;
  int Close() override;
  int FTruncate(off_t length) override;
  int FChMod(mode_t mode) override;
  ssize_t Writev(const struct iovec *iov, int iovcnt) override;
  ssize_t Readv(const struct iovec *iov, int iovcnt) override;
  ssize_t PRead(void *buf, size_t count, off_t offset) override;
  int SetSockOpt(int level, int option_name, const void *option_value,
                 socklen_t option_len) override;
  int Connect(const struct sockaddr *addr, socklen_t addrlen) override;
  int Shutdown(int how) override;
  ssize_t Send(const void *buf, size_t len, int flags) override;
  int GetSockOpt(int level, int optname, void *optval,
                 socklen_t *optlen) override;
  int Accept(struct sockaddr *addr, socklen_t *addrlen) override;
  int Bind(const struct sockaddr *addr, socklen_t addrlen) override;
  int Listen(int backlog) override;
  ssize_t SendMsg(const struct msghdr *msg, int flags) override;
  ssize_t RecvMsg(struct msghdr *msg, int flags) override;
  int GetSockName(struct sockaddr *addr, socklen_t *addrlen) override;
  int GetPeerName(struct sockaddr *addr, socklen_t *addrlen) override;
  ssize_t RecvFrom(void *buf, size_t len, int flags, struct sockaddr *src_addr,
                   socklen_t *addrlen) override;
  int GetHostFileDescriptor() override;

 private:
  // Host file descriptor implementing this stream.
  int host_fd_;
  void FillIov(const char *buf, int size, const struct iovec *iov, int iovcnt);
};

// VirtualPathHandler implementation handling paths to be forwarded to the host.
class NativePathHandler : public io::IOManager::VirtualPathHandler {
 public:
  std::unique_ptr<io::IOManager::IOContext> Open(const char *path, int flags,
                                                 mode_t mode) override;

  int Chown(const char *path, uid_t owner, gid_t group) override;
  int Link(const char *existing, const char *new_link) override;
  int Unlink(const char *pathname) override;
  ssize_t ReadLink(const char *path_name, char *buf, size_t bufsize) override;
  int SymLink(const char *path1, const char *path2) override;
  int Truncate(const char *path, off_t length) override;
  int Stat(const char *pathname, struct stat *stat_buffer) override;
  int StatFs(const char *pathname, struct statfs *statfs_buffer) override;
  int LStat(const char *pathname, struct stat *stat_buffer) override;
  ssize_t GetXattr(const char *path, const char *name, void *value,
                   size_t size) override;
  ssize_t LGetXattr(const char *path, const char *name, void *value,
                    size_t size) override;
  int SetXattr(const char *path, const char *name, const void *value,
               size_t size, int flags) override;
  int LSetXattr(const char *path, const char *name, const void *value,
                size_t size, int flags) override;
  ssize_t ListXattr(const char *path, char *list, size_t size) override;
  ssize_t LListXattr(const char *path, char *list, size_t size) override;
  int Mkdir(const char *path, mode_t mode) override;
  int RmDir(const char *pathname) override;
  int Rename(const char *oldpath, const char *newpath) override;
  int Access(const char *path, int mode) override;
  int ChMod(const char *pathname, mode_t mode) override;
  int Utime(const char *filename, const struct utimbuf *times) override;
  int Utimes(const char *filename, const struct timeval times[2]) override;
  int InotifyAddWatch(std::shared_ptr<IOManager::IOContext> context,
                      const char *pathname, uint32_t mask) override;
};

}  // namespace io
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_IO_NATIVE_PATHS_H_
