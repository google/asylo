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

#include "asylo/platform/posix/io/io_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>

#include "absl/algorithm/container.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/posix/io/native_paths.h"
#include "asylo/platform/posix/io/util.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace io {

IOManager::FileDescriptorTable::FileDescriptorTable()
    : maximum_fd_soft_limit(kMaxOpenFiles),
      maximum_fd_hard_limit(kMaxOpenFiles) {}

IOManager::IOContext *IOManager::FileDescriptorTable::Get(int fd) {
  if (!IsFileDescriptorValid(fd)) return nullptr;
  absl::MutexLock lock(&fd_table_lock_);
  return fd_table_[fd].get();
}

bool IOManager::FileDescriptorTable::HasSharedIOContext(int fd) {
  if (!IsFileDescriptorValid(fd)) return false;
  absl::MutexLock lock(&fd_table_lock_);
  return !fd_table_[fd].unique();
}

void IOManager::FileDescriptorTable::Delete(int fd) {
  if (!IsFileDescriptorValid(fd)) return;
  absl::MutexLock lock(&fd_table_lock_);
  fd_table_[fd] = nullptr;
}

bool IOManager::FileDescriptorTable::IsFileDescriptorUnused(int fd) {
  if (!IsFileDescriptorValid(fd)) return false;
  absl::MutexLock lock(&fd_table_lock_);
  return !fd_table_[fd];
}

int IOManager::FileDescriptorTable::Insert(IOContext *context) {
  absl::MutexLock lock(&fd_table_lock_);
  int fd = GetNextFreeFileDescriptor(0);
  if (fd < 0) {
    return -1;
  }
  fd_table_[fd] = std::shared_ptr<IOContext>(context);
  fd_to_lock_[fd];
  return fd;
}

int IOManager::FileDescriptorTable::CopyFileDescriptor(int oldfd, int startfd) {
  absl::MutexLock lock(&fd_table_lock_);
  int newfd = GetNextFreeFileDescriptor(startfd);
  if (!IsFileDescriptorValid(oldfd) || newfd == -1) {
    return -1;
  }
  fd_table_[newfd] = fd_table_[oldfd];
  // Insert a new Mutex lock corresponding to |newfd|.
  fd_to_lock_[newfd];
  return newfd;
}

int IOManager::FileDescriptorTable::CopyFileDescriptorToSpecifiedTarget(
    int oldfd, int newfd) {
  absl::MutexLock lock(&fd_table_lock_);
  if (!IsFileDescriptorValid(oldfd) || !IsFileDescriptorValid(newfd) ||
      fd_table_[newfd]) {
    return -1;
  }
  fd_table_[newfd] = fd_table_[oldfd];
  // Insert a new Mutex lock corresponding to |newfd|.
  fd_to_lock_[newfd];
  return newfd;
}

absl::Mutex *IOManager::FileDescriptorTable::GetLock(int fd) {
  if (!IsFileDescriptorValid(fd)) return nullptr;
  absl::MutexLock lock(&fd_table_lock_);
  auto it = fd_to_lock_.find(fd);
  if (it == fd_to_lock_.end()) return nullptr;
  return &(it->second);
}

bool IOManager::FileDescriptorTable::SetFileDescriptorLimits(
    const struct rlimit *rlim) {
  absl::MutexLock lock(&fd_table_lock_);
  // The new limit should not exceed the absolute max file limit, and
  // unprivileged process should not be allowed to increase the hard limit.
  if (rlim->rlim_cur > rlim->rlim_max || rlim->rlim_max > kMaxOpenFiles ||
      rlim->rlim_max <= GetHighestFileDescriptorUsed() ||
      rlim->rlim_max > maximum_fd_hard_limit) {
    return false;
  }
  maximum_fd_soft_limit = rlim->rlim_cur;
  maximum_fd_hard_limit = rlim->rlim_max;
  return true;
}

int IOManager::FileDescriptorTable::get_maximum_fd_soft_limit() {
  return maximum_fd_soft_limit;
}

int IOManager::FileDescriptorTable::get_maximum_fd_hard_limit() {
  return maximum_fd_hard_limit;
}

bool IOManager::FileDescriptorTable::IsFileDescriptorValid(int fd) {
  return fd >= 0 && fd < kMaxOpenFiles;
}

int IOManager::FileDescriptorTable::GetHighestFileDescriptorUsed() {
  for (int i = kMaxOpenFiles - 1; i >= 0; --i) {
    if (fd_table_[i]) {
      return i;
    }
  }
  return -1;
}

int IOManager::FileDescriptorTable::GetNextFreeFileDescriptor(int startfd) {
  if (startfd < 0) {
    return -1;
  }
  int fd = -1;
  for (int i = startfd; i < maximum_fd_soft_limit; ++i) {
    if (!fd_table_[i]) {
      fd = i;
      break;
    }
  }
  return fd;
}

int IOManager::Access(const char *path, int mode) {
  return CallWithHandler(
      path, [mode](VirtualPathHandler *handler, const char *canonical_path) {
        return handler->Access(canonical_path, mode);
      });
}

int IOManager::Close(int fd) {
  absl::Mutex *fd_lock = fd_table_.GetLock(fd);
  if (fd_lock) {
    absl::MutexLock lock(fd_lock);
    IOContext *context = fd_table_.Get(fd);
    if (context) {
      int ret = 0;
      // Only close the host file descriptor if this is the last reference to
      // it.
      if (!fd_table_.HasSharedIOContext(fd)) {
        ret = context->Close();
      }
      fd_table_.Delete(fd);
      return ret;
    }
  }
  errno = EBADF;
  return -1;
}

IOManager::VirtualPathHandler *IOManager::HandlerForPath(
    absl::string_view path) const {
  // Start by looking for a full match.
  std::string current_prefix(path);

  // Keep looking until we find a match or run out of handlers to check.
  while (true) {
    // Find the first handler with a prefix greater or equal to this path.
    // If there is an exact match, this will be it.  Otherwise, any match must
    // be before this.
    auto iter = prefix_to_handler_.lower_bound(current_prefix);

    // iter->first is the registered prefix.
    // iter->second.get() is a pointer to the registered handler.

    // lower_bound can land directory on a match.
    if (iter != prefix_to_handler_.end() && current_prefix == iter->first) {
      return iter->second.get();
    }

    // Since we started with the lower_bound, any prefixes will be found
    // before that iterator.  If there are none, we're done.
    if (iter == prefix_to_handler_.begin()) break;
    --iter;

    // Determine how much this handler's prefix and the current prefix have in
    // common.
    std::string::const_iterator end_prefix, end_path;
    std::tie(end_prefix, end_path) =
        absl::c_mismatch(iter->first, current_prefix);

    // If the entire prefix is in the current prefix up to a /, it's a match.
    if (end_prefix == iter->first.end() && *end_path == '/') {
      return iter->second.get();
    }

    // Back up the prefix to nearest directory.  We know there can't be a
    // matching handler with a longer prefix match or we would have found it by
    // now.
    while (*end_prefix != '/') --end_prefix;

    // The next iteration of the loop will look for a matching handler using
    // that directory prefix.
    current_prefix = std::string(iter->first.begin(), end_prefix);
  }

  // Didn't find a handler.
  return nullptr;
}

int IOManager::Open(const char *path, int flags, mode_t mode) {
  return CallWithHandler(path, [flags, mode, this](VirtualPathHandler *handler,
                                                   const char *canonical_path) {
    std::unique_ptr<IOContext> context =
        handler->Open(canonical_path, flags, mode);

    if (context) {
      int fd = fd_table_.Insert(context.get());
      if (fd >= 0) {
        context.release();
        return fd;
      }
      errno = ENFILE;
    }
    return -1;
  });
}

int IOManager::Dup(int oldfd) {
  absl::Mutex *fd_lock = fd_table_.GetLock(oldfd);
  if (fd_lock) {
    absl::MutexLock lock(fd_lock);
    if (!fd_table_.IsFileDescriptorUnused(oldfd)) {
      int ret = fd_table_.CopyFileDescriptor(oldfd, 0);
      if (ret < 0) {
        errno = EINVAL;
      }
      return ret;
    }
  }
  errno = EBADF;
  return -1;
}

int IOManager::Dup2(int oldfd, int newfd) {
  absl::Mutex *fd_lock = fd_table_.GetLock(oldfd);
  if (fd_lock) {
    absl::MutexLock lock(fd_lock);
    if (!fd_table_.IsFileDescriptorUnused(oldfd)) {
      if (oldfd == newfd) {
        return newfd;
      }
      if (!fd_table_.IsFileDescriptorUnused(newfd) && Close(newfd) == -1) {
        return -1;
      }
      int ret = fd_table_.CopyFileDescriptorToSpecifiedTarget(oldfd, newfd);
      if (ret < 0) {
        errno = EINVAL;
      }
      return ret;
    }
  }
  errno = EBADF;
  return -1;
}

int IOManager::Pipe(int pipefd[2]) {
  int res = enc_untrusted_pipe(pipefd);
  if (res != -1) {
    pipefd[0] = RegisterHostFileDescriptor(pipefd[0]);
    pipefd[1] = RegisterHostFileDescriptor(pipefd[1]);
    if (pipefd[0] < 0 || pipefd[1] < 0) {
      errno = EMFILE;
      return -1;
    }
  }
  return res;
}

int IOManager::Poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  std::vector<int> enclave_fd(nfds);
  for (int i = 0; i < nfds; ++i) {
    enclave_fd[i] = fds[i].fd;
    IOContext *context = fd_table_.Get(enclave_fd[i]);
    if (context) {
      fds[i].fd = context->GetHostFileDescriptor();
    } else {
      fds[i].fd = -1;
    }
  }
  int ret = enc_untrusted_poll(fds, nfds, timeout);
  for (int i = 0; i < nfds; ++i) {
    fds[i].fd = enclave_fd[i];
  }
  return ret;
}

template <typename IOAction>
int IOManager::LockAndRoll(int fd, IOAction action) {
  absl::Mutex *fd_lock = fd_table_.GetLock(fd);
  if (fd_lock) {
    absl::MutexLock lock(fd_lock);
    IOContext *context = fd_table_.Get(fd);
    if (context) {
      return action(context);
    }
  }
  errno = EBADF;
  return -1;
}

template <typename IOAction>
typename std::result_of<IOAction(IOManager::VirtualPathHandler *,
                                 const char *)>::type
IOManager::CallWithHandler(const char *path, IOAction action) {
  StatusOr<std::string> status = CanonicalizePath(path);
  if (!status.ok()) {
    errno = status.status().error_code();
    return -1;
  }

  absl::string_view canonical_path = status.ValueOrDie();
  VirtualPathHandler *handler = HandlerForPath(canonical_path);
  if (handler) {
    // Invoke the path handler if one is installed.
    return action(handler, canonical_path.data());
  }

  errno = ENOENT;
  return -1;
}

template <typename IOAction>
typename std::result_of<IOAction(IOManager::VirtualPathHandler *, const char *,
                                 const char *)>::type
IOManager::CallWithHandler(const char *path1, const char *path2,
                           IOAction action) {
  StatusOr<std::string> status1 = CanonicalizePath(path1);
  StatusOr<std::string> status2 = CanonicalizePath(path2);
  if (!status1.ok()) {
    errno = status1.status().error_code();
    return -1;
  }
  if (!status2.ok()) {
    errno = status2.status().error_code();
    return -1;
  }

  absl::string_view canonical_path1 = status1.ValueOrDie();
  absl::string_view canonical_path2 = status2.ValueOrDie();
  VirtualPathHandler *handler1 = HandlerForPath(canonical_path1);
  VirtualPathHandler *handler2 = HandlerForPath(canonical_path2);
  if (handler1 != handler2) {
    errno = EXDEV;
    return -1;
  }

  if (handler1) {
    // Invoke the path handler if one is installed.
    return action(handler1, canonical_path1.data(), canonical_path2.data());
  }

  errno = ENOENT;
  return -1;
}

int IOManager::Read(int fd, char *buf, size_t count) {
  return LockAndRoll(fd, [buf, count](IOContext *context) {
    return context->Read(buf, count);
  });
}

bool IOManager::RegisterVirtualPathHandler(
    const std::string &path_prefix, std::unique_ptr<VirtualPathHandler> handler) {
  if (!handler || (!path_prefix.empty() &&
                   (path_prefix.front() != '/' || path_prefix.back() == '/'))) {
    return false;
  }

  prefix_to_handler_.emplace(path_prefix, std::move(handler));
  return true;
}

void IOManager::DeregisterVirtualPathHandler(const std::string &path_prefix) {
  prefix_to_handler_.erase(path_prefix);
}

Status IOManager::SetCurrentWorkingDirectory(absl::string_view path) {
  StatusOr<std::string> working_directory = CanonicalizePath(path);
  Status status = working_directory.status();
  if (status.ok()) {
    current_working_directory_ = working_directory.ValueOrDie();
  }

  return status;
}

std::string IOManager::GetCurrentWorkingDirectory() const {
  return current_working_directory_;
}

StatusOr<std::string> IOManager::CanonicalizePath(absl::string_view path) const {
  // Cannot resolve an empty path.
  if (path.empty()) {
    return Status(error::PosixError::P_ENOENT,
                  "Cannot canonicalize empty path");
  }

  // In some cases, the handler may be restricted for a given path.
  // By default, though, any handler is fine.
  VirtualPathHandler *required_handler = nullptr;

  // Handle relative paths.
  std::string relative_path;
  if (path.front() != '/') {
    std::string working_directory = GetCurrentWorkingDirectory();

    // If the current working directory has not yet been set, cannot
    // canonicalize relative paths.
    if (working_directory.empty()) {
      return Status(error::PosixError::P_ENOENT,
                    "Canonicalization of relative path before initialization");
    }

    // Prepend the working directory to the given path. Don't worry about
    // possible duplicate '/' characters, as NormalizePath will strip them out.
    relative_path = absl::StrCat(working_directory, "/", path);
    path = relative_path;

    // Relative paths are only allowed to resolve to the same handler as the
    // working directory.
    required_handler = HandlerForPath(working_directory);
  }

  // Normalize the path to remove any directory traversals.
  std::string ret = util::NormalizePath(path);

  // If the allowed handler for this path is restricted, check that it matches
  // the requirement.
  if (required_handler && HandlerForPath(ret) != required_handler) {
    return Status(error::PosixError::P_EACCES,
                  "Relative path resolution across access domains");
  }

  return ret;
}

int IOManager::Write(int fd, const char *buf, size_t count) {
  return LockAndRoll(fd, [buf, count](IOContext *context) {
    return context->Write(buf, count);
  });
}

int IOManager::Chown(const char *path, uid_t owner, gid_t group) {
  return CallWithHandler(path, [owner, group](VirtualPathHandler *handler,
                                              const char *canonical_path) {
    return handler->Chown(canonical_path, owner, group);
  });
}

int IOManager::Link(const char *from, const char *to) {
  return CallWithHandler(
      from, to,
      [](VirtualPathHandler *handler, const char *canonical_from,
         const char *canonical_to) {
        return handler->Link(canonical_from, canonical_to);
      });
}

int IOManager::Unlink(const char *pathname) {
  return CallWithHandler(
      pathname, [](VirtualPathHandler *handler, const char *canonical_path) {
        return handler->Unlink(canonical_path);
      });
}

ssize_t IOManager::ReadLink(const char *path, char *buf, size_t bufsize) {
  return CallWithHandler(path, [buf, bufsize](VirtualPathHandler *handler,
                                              const char *canonical_path) {
    return handler->ReadLink(canonical_path, buf, bufsize);
  });
}

int IOManager::SymLink(const char *from, const char *to) {
  return CallWithHandler(
      from, to,
      [](VirtualPathHandler *handler, const char *canonical_from,
         const char *canonical_to) {
        return handler->SymLink(canonical_from, canonical_to);
      });
}

int IOManager::Stat(const char *pathname, struct stat *stat_buffer) {
  return CallWithHandler(pathname, [stat_buffer](VirtualPathHandler *handler,
                                                 const char *canonical_path) {
    return handler->Stat(canonical_path, stat_buffer);
  });
}

int IOManager::LStat(const char *pathname, struct stat *stat_buffer) {
  return CallWithHandler(pathname, [stat_buffer](VirtualPathHandler *handler,
                                                 const char *canonical_path) {
    return handler->LStat(canonical_path, stat_buffer);
  });
}

int IOManager::LSeek(int fd, off_t offset, int whence) {
  return LockAndRoll(fd, [offset, whence](IOContext *context) {
    return context->LSeek(offset, whence);
  });
}

int IOManager::FCntl(int fd, int cmd, int64_t arg) {
  if (cmd == F_DUPFD) {
    absl::Mutex *fd_lock = fd_table_.GetLock(fd);
    if (fd_lock) {
      absl::MutexLock lock(fd_lock);
      if (!fd_table_.IsFileDescriptorUnused(fd)) {
        int ret = fd_table_.CopyFileDescriptor(fd, arg);
        if (ret < 0) {
          errno = EINVAL;
        }
        return ret;
      }
    }
    errno = EBADF;
    return -1;
  }
  return LockAndRoll(
      fd, [cmd, arg](IOContext *context) { return context->FCntl(cmd, arg); });
}

int IOManager::FSync(int fd) {
  return LockAndRoll(fd, [](IOContext *context) { return context->FSync(); });
}

int IOManager::FStat(int fd, struct stat *stat_buffer) {
  return LockAndRoll(fd, [stat_buffer](IOContext *context) {
    return context->FStat(stat_buffer);
  });
}

int IOManager::Isatty(int fd) {
  return LockAndRoll(fd, [](IOContext *context) { return context->Isatty(); });
}

int IOManager::Ioctl(int fd, int request, void *argp) {
  return LockAndRoll(fd, [request, argp](IOContext *context) {
    return context->Ioctl(request, argp);
  });
}

int IOManager::Mkdir(const char *path, mode_t mode) {
  return CallWithHandler(
      path, [mode](VirtualPathHandler *handler, const char *canonical_path) {
        return handler->Mkdir(canonical_path, mode);
      });
}

ssize_t IOManager::Writev(int fd, const struct iovec *iov, int iovcnt) {
  return LockAndRoll(fd, [iov, iovcnt](IOContext *context) {
    return context->Writev(iov, iovcnt);
  });
}

ssize_t IOManager::Readv(int fd, const struct iovec *iov, int iovcnt) {
  return LockAndRoll(fd, [iov, iovcnt](IOContext *context) {
    return context->Readv(iov, iovcnt);
  });
}

mode_t IOManager::Umask(mode_t mask) { return enc_untrusted_umask(mask); }

int IOManager::GetRLimit(int resource, struct rlimit *rlim) {
  if (!rlim) {
    errno = EFAULT;
    return -1;
  }
  switch (resource) {
    case RLIMIT_NOFILE:
      rlim->rlim_cur = fd_table_.get_maximum_fd_soft_limit();
      rlim->rlim_max = fd_table_.get_maximum_fd_hard_limit();
      return 0;
    default:
      errno = ENOSYS;
      return -1;
  }
}

int IOManager::SetRLimit(int resource, const struct rlimit *rlim) {
  if (!rlim) {
    errno = EFAULT;
    return -1;
  }
  if (rlim->rlim_cur > rlim->rlim_max || rlim->rlim_cur < 0) {
    errno = EINVAL;
    return -1;
  }
  switch (resource) {
    case RLIMIT_NOFILE:
      if (!fd_table_.SetFileDescriptorLimits(rlim)) {
        errno = EPERM;
        return -1;
      }
      return 0;
    default:
      errno = ENOSYS;
      return -1;
  }
}

int IOManager::SetSockOpt(int sockfd, int level, int option_name,
                          const void *option_value, socklen_t option_len) {
  return LockAndRoll(sockfd, [level, option_name, option_value,
                              option_len](IOContext *context) {
    return context->SetSockOpt(level, option_name, option_value, option_len);
  });
}

int IOManager::Connect(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {
  return LockAndRoll(sockfd, [addr, addrlen](IOContext *context) {
    return context->Connect(addr, addrlen);
  });
}

int IOManager::Shutdown(int sockfd, int how) {
  return LockAndRoll(
      sockfd, [how](IOContext *context) { return context->Shutdown(how); });
}

ssize_t IOManager::Send(int sockfd, const void *buf, size_t len, int flags) {
  return LockAndRoll(sockfd, [buf, len, flags](IOContext *context) {
    return context->Send(buf, len, flags);
  });
}

int IOManager::Socket(int domain, int type, int protocol) {
  int socket = enc_untrusted_socket(domain, type, protocol);
  if (socket == -1) {
    return -1;
  }

  int ret = this->RegisterHostFileDescriptor(socket);
  if (ret < 0) {
    errno = EMFILE;
  }
  return ret;
}

int IOManager::GetSockOpt(int sockfd, int level, int optname, void *optval,
                          socklen_t *optlen) {
  return LockAndRoll(
      sockfd, [level, optname, optval, optlen](IOContext *context) {
        return context->GetSockOpt(level, optname, optval, optlen);
      });
}

int IOManager::Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int ret = LockAndRoll(sockfd, [addr, addrlen](IOContext *context) {
    return context->Accept(addr, addrlen);
  });
  if (ret < 0) {
    return -1;
  }
  ret = this->RegisterHostFileDescriptor(ret);
  if (ret < 0) {
    errno = EMFILE;
  }
  return ret;
}

int IOManager::Bind(int sockfd, const struct sockaddr *addr,
                    socklen_t addrlen) {
  return LockAndRoll(sockfd, [addr, addrlen](IOContext *context) {
    return context->Bind(addr, addrlen);
  });
}

int IOManager::Listen(int sockfd, int backlog) {
  return LockAndRoll(sockfd, [backlog](IOContext *context) {
    return context->Listen(backlog);
  });
}

ssize_t IOManager::SendMsg(int sockfd, const struct msghdr *msg, int flags) {
  return LockAndRoll(sockfd, [msg, flags](IOContext *context) {
    return context->SendMsg(msg, flags);
  });
}

ssize_t IOManager::RecvMsg(int sockfd, struct msghdr *msg, int flags) {
  return LockAndRoll(sockfd, [msg, flags](IOContext *context) {
    return context->RecvMsg(msg, flags);
  });
}

int IOManager::GetSockName(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen) {
  return LockAndRoll(sockfd, [addr, addrlen](IOContext *context) {
    return context->GetSockName(addr, addrlen);
  });
}

int IOManager::GetPeerName(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen) {
  return LockAndRoll(sockfd, [addr, addrlen](IOContext *context) {
    return context->GetPeerName(addr, addrlen);
  });
}

int IOManager::RegisterHostFileDescriptor(int host_fd) {
  auto context = ::absl::make_unique<IOContextNative>(host_fd);
  int fd = fd_table_.Insert(context.get());
  if (fd >= 0) {
    context.release();
    return fd;
  }
  return -1;
}

}  // namespace io
}  // namespace asylo
