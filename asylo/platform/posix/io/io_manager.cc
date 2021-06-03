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

#include <fcntl.h>
#include <poll.h>

#include <cerrno>
#include <cstdint>
#include <memory>
#include <unordered_set>

#include "absl/algorithm/container.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/io/io_context_epoll.h"
#include "asylo/platform/posix/io/io_context_eventfd.h"
#include "asylo/platform/posix/io/io_context_inotify.h"
#include "asylo/platform/posix/io/native_paths.h"
#include "asylo/platform/posix/io/util.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace io {

IOManager::FileDescriptorTable::FileDescriptorTable()
    : maximum_fd_soft_limit(kMaxOpenFiles),
      maximum_fd_hard_limit(kMaxOpenFiles) {}

std::shared_ptr<IOManager::IOContext> IOManager::FileDescriptorTable::Get(
    int fd) {
  if (!IsFileDescriptorValid(fd) || !fd_table_[fd]) return nullptr;
  return fd_table_[fd]->Get();
}

int IOManager::FileDescriptorTable::Delete(int fd) {
  if (!IsFileDescriptorValid(fd)) return 0;
  int close_result = 0;
  fd_table_[fd]->WriteCloseResultTo(&close_result);
  fd_table_[fd] = nullptr;
  return close_result;
}

bool IOManager::FileDescriptorTable::IsFileDescriptorUnused(int fd) {
  if (!IsFileDescriptorValid(fd)) return false;
  return !fd_table_[fd];
}

int IOManager::FileDescriptorTable::Insert(IOContext *context) {
  int fd = GetNextFreeFileDescriptor(0);
  if (fd < 0) {
    return -1;
  }
  fd_table_[fd] = std::make_shared<AutoCloseIOContext>(context);
  return fd;
}

int IOManager::FileDescriptorTable::CopyFileDescriptor(int oldfd, int startfd) {
  int newfd = GetNextFreeFileDescriptor(startfd);
  if (!IsFileDescriptorValid(oldfd) || newfd == -1) {
    return -1;
  }
  fd_table_[newfd] = fd_table_[oldfd];
  return newfd;
}

int IOManager::FileDescriptorTable::CopyFileDescriptorToSpecifiedTarget(
    int oldfd, int newfd) {
  if (!IsFileDescriptorValid(oldfd) || !IsFileDescriptorValid(newfd) ||
      fd_table_[newfd]) {
    return -1;
  }
  fd_table_[newfd] = fd_table_[oldfd];
  return newfd;
}

bool IOManager::FileDescriptorTable::SetFileDescriptorLimits(
    const struct rlimit *rlim) {
  // The new limit should not exceed the absolute max file limit, and
  // unprivileged process should not be allowed to increase the hard limit.
  if (rlim->rlim_max <= GetHighestFileDescriptorUsed()) {
    errno = EINVAL;
    return false;
  }
  if (rlim->rlim_cur > rlim->rlim_max || rlim->rlim_max > kMaxOpenFiles ||
      rlim->rlim_max > maximum_fd_hard_limit) {
    errno = EPERM;
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

int IOManager::CloseFileDescriptor(int fd) {
  std::shared_ptr<IOContext> context = fd_table_.Get(fd);
  if (context) {
    return fd_table_.Delete(fd);
  }
  errno = EBADF;
  return -1;
}

int IOManager::Close(int fd) {
  absl::WriterMutexLock lock(&fd_table_lock_);
  return CloseFileDescriptor(fd);
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
      absl::WriterMutexLock lock(&fd_table_lock_);
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
  absl::WriterMutexLock lock(&fd_table_lock_);
  if (!fd_table_.IsFileDescriptorUnused(oldfd)) {
    int ret = fd_table_.CopyFileDescriptor(oldfd, 0);
    if (ret < 0) {
      errno = EINVAL;
    }
    return ret;
  }
  errno = EBADF;
  return -1;
}

int IOManager::Dup2(int oldfd, int newfd) {
  absl::WriterMutexLock lock(&fd_table_lock_);
  if (!fd_table_.IsFileDescriptorUnused(oldfd)) {
    if (oldfd == newfd) {
      return newfd;
    }
    if (!fd_table_.IsFileDescriptorUnused(newfd) &&
        CloseFileDescriptor(newfd) == -1) {
      return -1;
    }
    int ret = fd_table_.CopyFileDescriptorToSpecifiedTarget(oldfd, newfd);
    if (ret < 0) {
      errno = EINVAL;
    }
    return ret;
  }
  errno = EBADF;
  return -1;
}

int IOManager::Pipe(int pipefd[2], int flags) {
  int res = enc_untrusted_pipe2(pipefd, flags);
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

int IOManager::Select(int nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *exceptfds, struct timeval *timeout) {
  if (nfds < 0) {
    errno = EINVAL;
    return -1;
  }

  // Translate the fd_sets into host file descriptors.
  fd_set host_readfds, host_writefds, host_exceptfds;
  FD_ZERO(&host_readfds);
  FD_ZERO(&host_writefds);
  FD_ZERO(&host_exceptfds);

  int host_nfds = 0;
  for (int fd = 0; fd < nfds; ++fd) {
    if (readfds && FD_ISSET(fd, readfds)) {
      std::shared_ptr<IOContext> context = fd_table_.Get(fd);
      if (context) {
        int host_fd = context->GetHostFileDescriptor();
        FD_SET(host_fd, &host_readfds);
        host_nfds = std::max(host_nfds, host_fd + 1);
      }
    }
    if (writefds && FD_ISSET(fd, writefds)) {
      std::shared_ptr<IOContext> context = fd_table_.Get(fd);
      if (context) {
        int host_fd = context->GetHostFileDescriptor();
        FD_SET(host_fd, &host_writefds);
        host_nfds = std::max(host_nfds, host_fd + 1);
      }
    }
    if (exceptfds && FD_ISSET(fd, exceptfds)) {
      std::shared_ptr<IOContext> context = fd_table_.Get(fd);
      if (context) {
        int host_fd = context->GetHostFileDescriptor();
        FD_SET(host_fd, &host_exceptfds);
        host_nfds = std::max(host_nfds, host_fd + 1);
      }
    }
  }
  int ret = enc_untrusted_select(host_nfds, &host_readfds, &host_writefds,
                                 &host_exceptfds, timeout);

  // On error, errno should have been set by the host.
  if (ret < 0) {
    return ret;
  }

  // Add the returned fd_sets into an unordered set. IOManager is used in
  // trusted contexts where system calls might not be available; avoid using
  // absl based containers which may perform system calls.
  std::unordered_set<int> host_readfds_set, host_writefds_set,
      host_exceptfds_set;
  for (int fd = 0; fd < nfds; ++fd) {
    std::shared_ptr<IOContext> context = fd_table_.Get(fd);
    if (context) {
      int host_fd = context->GetHostFileDescriptor();
      if (host_fd < 0) continue;
      if (FD_ISSET(host_fd, &host_readfds)) {
        host_readfds_set.insert(host_fd);
      }
      if (FD_ISSET(host_fd, &host_writefds)) {
        host_writefds_set.insert(host_fd);
      }
      if (FD_ISSET(host_fd, &host_exceptfds)) {
        host_exceptfds_set.insert(host_fd);
      }
    }
  }

  if (readfds) {
    FD_ZERO(readfds);
  }
  if (writefds) {
    FD_ZERO(writefds);
  }
  if (exceptfds) {
    FD_ZERO(exceptfds);
  }
  // Go through the file descriptor table, if any host file descriptor is
  // included in any of the sets, add the corresponding enclave fd to the
  // enclave fd_set.
  for (int fd = 0; fd < nfds; ++fd) {
    std::shared_ptr<IOContext> context = fd_table_.Get(fd);
    if (context) {
      int host_fd = context->GetHostFileDescriptor();
      if (readfds && host_readfds_set.find(host_fd) != host_readfds_set.end()) {
        FD_SET(fd, readfds);
      }
      if (writefds &&
          host_writefds_set.find(host_fd) != host_writefds_set.end()) {
        FD_SET(fd, writefds);
      }
      if (exceptfds &&
          host_exceptfds_set.find(host_fd) != host_exceptfds_set.end()) {
        FD_SET(fd, exceptfds);
      }
    }
  }
  return ret;
}

int IOManager::Poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  std::vector<int> enclave_fd(nfds);
  {
    absl::ReaderMutexLock lock(&fd_table_lock_);
    for (int i = 0; i < nfds; ++i) {
      enclave_fd[i] = fds[i].fd;
      std::shared_ptr<IOContext> context = fd_table_.Get(enclave_fd[i]);
      if (context) {
        fds[i].fd = context->GetHostFileDescriptor();
      } else {
        fds[i].fd = -1;
      }
    }
  }
  int ret = enc_untrusted_poll(fds, nfds, timeout);
  for (int i = 0; i < nfds; ++i) {
    fds[i].fd = enclave_fd[i];
  }
  return ret;
}

int IOManager::EpollCreate(int size) {
  if (size < 1) {
    errno = EINVAL;
    return -1;
  }
  int hostfd = enc_untrusted_epoll_create(size);
  if (hostfd == -1) {
    return -1;
  }
  auto context = ::absl::make_unique<IOContextEpoll>(hostfd);
  absl::WriterMutexLock lock(&fd_table_lock_);
  int fd = fd_table_.Insert(context.get());
  if (fd >= 0) {
    context.release();
    return fd;
  }
  errno = EMFILE;
  return -1;
}

int IOManager::EpollCtl(int epfd, int op, int fd, struct epoll_event *event) {
  std::shared_ptr<IOContext> context;
  {
    absl::ReaderMutexLock lock(&fd_table_lock_);
    context = fd_table_.Get(fd);
  }
  int hostfd = context ? context->GetHostFileDescriptor() : -1;
  if (hostfd == -1) {
    errno = EBADF;
    return -1;
  }
  return CallWithContext(
      epfd, [op, hostfd, event](std::shared_ptr<IOContext> epoll_context) {
        return epoll_context->EpollCtl(op, hostfd, event);
      });
}

int IOManager::EpollWait(int epfd, struct epoll_event *events, int maxevents,
                         int timeout) {
  return CallWithContext(
      epfd, [events, maxevents, timeout](std::shared_ptr<IOContext> context) {
        return context->EpollWait(events, maxevents, timeout);
      });
}

int IOManager::EventFd(unsigned int initval, int flags) {
  auto context = ::absl::make_unique<IOContextEventFd>(initval, flags);
  absl::WriterMutexLock lock(&fd_table_lock_);
  int fd = fd_table_.Insert(context.get());
  if (fd >= 0) {
    context.release();
    return fd;
  }
  errno = EMFILE;
  return -1;
}

int IOManager::InotifyInit(bool non_block) {
  int hostfd = enc_untrusted_inotify_init1(non_block);
  if (hostfd == -1) {
    return -1;
  }
  auto context = ::absl::make_unique<IOContextInotify>(hostfd);
  absl::WriterMutexLock lock(&fd_table_lock_);
  int fd = fd_table_.Insert(context.get());
  if (fd >= 0) {
    context.release();
    return fd;
  }
  errno = EMFILE;
  return -1;
}

int IOManager::InotifyAddWatch(int fd, const char *pathname, uint32_t mask) {
  return CallWithContext(
      fd, [this, pathname, mask](std::shared_ptr<IOContext> inotify_context) {
        return CallWithHandler(
            pathname, [inotify_context, mask](VirtualPathHandler *handler,
                                              const char *canonical_path) {
              return handler->InotifyAddWatch(inotify_context, canonical_path,
                                              mask);
            });
      });
}

int IOManager::InotifyRmWatch(int fd, int wd) {
  return CallWithContext(fd, [wd](std::shared_ptr<IOContext> inotify_context) {
    return inotify_context->InotifyRmWatch(wd);
  });
}

// Provide a proper error return value of different types for use in templates.
namespace {

template <typename Type, typename = void>
struct ErrorValue;

// Actions returning signed arithmetic types (e.g., int, ssize_t) indicate
// error with -1.
template <typename Type>
struct ErrorValue<Type,
                  typename std::enable_if<std::is_signed<Type>::value>::type> {
  static constexpr Type value = -1;
};

// Actions returning pointer types indicate error with nullptr.
template <typename Type>
struct ErrorValue<Type,
                  typename std::enable_if<std::is_pointer<Type>::value>::type> {
  static constexpr Type value = nullptr;
};

}  // namespace

template <typename IOAction, typename ReturnType>
ReturnType IOManager::CallWithContext(int fd, IOAction action) {
  std::shared_ptr<IOContext> context;
  {
    absl::ReaderMutexLock lock(&fd_table_lock_);
    context = fd_table_.Get(fd);
  }
  if (context) {
    return action(context);
  }
  errno = EBADF;
  return ErrorValue<ReturnType>::value;
}

template <typename IOAction, typename ReturnType>
ReturnType IOManager::CallWithHandler(const char *path, IOAction action) {
  StatusOr<std::string> status = CanonicalizePath(path);
  if (!status.ok()) {
    errno = GetErrno(status.status());
    return ErrorValue<ReturnType>::value;
  }

  absl::string_view canonical_path = status.value();
  VirtualPathHandler *handler = HandlerForPath(canonical_path);
  if (handler) {
    // Invoke the path handler if one is installed.
    return action(handler, canonical_path.data());
  }

  errno = ENOENT;
  return ErrorValue<ReturnType>::value;
}

template <typename IOAction, typename ReturnType>
ReturnType IOManager::CallWithHandler(const char *path1, const char *path2,
                                      IOAction action) {
  StatusOr<std::string> status1 = CanonicalizePath(path1);
  if (!status1.ok()) {
    errno = GetErrno(status1.status());
    return ErrorValue<ReturnType>::value;
  }
  StatusOr<std::string> status2 = CanonicalizePath(path2);
  if (!status2.ok()) {
    errno = GetErrno(status2.status());
    return ErrorValue<ReturnType>::value;
  }

  absl::string_view canonical_path1 = status1.value();
  absl::string_view canonical_path2 = status2.value();
  VirtualPathHandler *handler1 = HandlerForPath(canonical_path1);
  VirtualPathHandler *handler2 = HandlerForPath(canonical_path2);
  if (handler1 != handler2) {
    errno = EXDEV;
    return ErrorValue<ReturnType>::value;
  }

  if (handler1) {
    // Invoke the path handler if one is installed.
    return action(handler1, canonical_path1.data(), canonical_path2.data());
  }

  errno = ENOENT;
  return ErrorValue<ReturnType>::value;
}

int IOManager::Read(int fd, char *buf, size_t count) {
  return CallWithContext(fd, [buf, count](std::shared_ptr<IOContext> context) {
    return context->Read(buf, count);
  });
}

bool IOManager::RegisterVirtualPathHandler(
    const std::string &path_prefix,
    std::unique_ptr<VirtualPathHandler> handler) {
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
    current_working_directory_ = working_directory.value();
  }

  return status;
}

std::string IOManager::GetCurrentWorkingDirectory() const {
  return current_working_directory_;
}

StatusOr<std::string> IOManager::CanonicalizePath(
    absl::string_view path) const {
  // Cannot resolve an empty path.
  if (path.empty()) {
    return PosixError(ENOENT, "Cannot canonicalize empty path");
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
      return PosixError(
          ENOENT, "Canonicalization of relative path before initialization");
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
    return PosixError(EACCES, "Relative path resolution across access domains");
  }

  return ret;
}

int IOManager::Write(int fd, const char *buf, size_t count) {
  return CallWithContext(fd, [buf, count](std::shared_ptr<IOContext> context) {
    return context->Write(buf, count);
  });
}

int IOManager::Chown(const char *path, uid_t owner, gid_t group) {
  return CallWithHandler(path, [owner, group](VirtualPathHandler *handler,
                                              const char *canonical_path) {
    return handler->Chown(canonical_path, owner, group);
  });
}

char *IOManager::RealPath(const char *path, char *resolved_path) {
  StatusOr<std::string> path_str_or = CanonicalizePath(path);
  if (!path_str_or.ok()) {
    errno = GetErrno(path_str_or.status());

    return nullptr;
  }
  std::string path_str = path_str_or.value();
  if (resolved_path) {
    snprintf(resolved_path, PATH_MAX, "%s", path_str.c_str());
    return resolved_path;
  }
  return strdup(path_str.c_str());
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

int IOManager::Truncate(const char *path, off_t length) {
  return CallWithHandler(
      path, [length](VirtualPathHandler *handler, const char *canonical_path) {
        return handler->Truncate(canonical_path, length);
      });
}

int IOManager::FTruncate(int fd, off_t length) {
  return CallWithContext(fd, [length](std::shared_ptr<IOContext> context) {
    return context->FTruncate(length);
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

int IOManager::StatFs(const char *pathname, struct statfs *statfs_buffer) {
  return CallWithHandler(pathname, [statfs_buffer](VirtualPathHandler *handler,
                                                   const char *canonical_path) {
    return handler->StatFs(canonical_path, statfs_buffer);
  });
}

ssize_t IOManager::GetXattr(const char *path, const char *name, void *value,
                            size_t size) {
  return CallWithHandler(path, [name, value, size](VirtualPathHandler *handler,
                                                   const char *canonical_path) {
    return handler->GetXattr(canonical_path, name, value, size);
  });
}

ssize_t IOManager::LGetXattr(const char *path, const char *name, void *value,
                             size_t size) {
  return CallWithHandler(path, [name, value, size](VirtualPathHandler *handler,
                                                   const char *canonical_path) {
    return handler->LGetXattr(canonical_path, name, value, size);
  });
}

int IOManager::SetXattr(const char *path, const char *name, const void *value,
                        size_t size, int flags) {
  return CallWithHandler(
      path, [name, value, size, flags](VirtualPathHandler *handler,
                                       const char *canonical_path) {
        return handler->SetXattr(canonical_path, name, value, size, flags);
      });
}

int IOManager::LSetXattr(const char *path, const char *name, const void *value,
                         size_t size, int flags) {
  return CallWithHandler(
      path, [name, value, size, flags](VirtualPathHandler *handler,
                                       const char *canonical_path) {
        return handler->LSetXattr(canonical_path, name, value, size, flags);
      });
}

ssize_t IOManager::ListXattr(const char *path, char *list, size_t size) {
  return CallWithHandler(path, [list, size](VirtualPathHandler *handler,
                                            const char *canonical_path) {
    return handler->ListXattr(canonical_path, list, size);
  });
}

ssize_t IOManager::LListXattr(const char *path, char *list, size_t size) {
  return CallWithHandler(path, [list, size](VirtualPathHandler *handler,
                                            const char *canonical_path) {
    return handler->LListXattr(canonical_path, list, size);
  });
}

int IOManager::ChMod(const char *pathname, mode_t mode) {
  return CallWithHandler(pathname, [mode](VirtualPathHandler *handler,
                                          const char *canonical_path) {
    return handler->ChMod(canonical_path, mode);
  });
}

int IOManager::FChOwn(int fd, uid_t owner, gid_t group) {
  return CallWithContext(fd,
                         [owner, group](std::shared_ptr<IOContext> context) {
                           return context->FChOwn(owner, group);
                         });
}

int IOManager::FChMod(int fd, mode_t mode) {
  return CallWithContext(fd, [mode](std::shared_ptr<IOContext> context) {
    return context->FChMod(mode);
  });
}

int IOManager::LSeek(int fd, off_t offset, int whence) {
  return CallWithContext(fd,
                         [offset, whence](std::shared_ptr<IOContext> context) {
                           return context->LSeek(offset, whence);
                         });
}

int IOManager::FCntl(int fd, int cmd, int64_t arg) {
  if (cmd == F_DUPFD) {
    absl::WriterMutexLock lock(&fd_table_lock_);
    if (!fd_table_.IsFileDescriptorUnused(fd)) {
      int ret = fd_table_.CopyFileDescriptor(fd, arg);
      if (ret < 0) {
        errno = EINVAL;
      }
      return ret;
    }
    errno = EBADF;
    return -1;
  }
  return CallWithContext(fd, [cmd, arg](std::shared_ptr<IOContext> context) {
    return context->FCntl(cmd, arg);
  });
}

int IOManager::FSync(int fd) {
  return CallWithContext(
      fd, [](std::shared_ptr<IOContext> context) { return context->FSync(); });
}

int IOManager::FDataSync(int fd) {
  return CallWithContext(fd, [](std::shared_ptr<IOContext> context) {
    return context->FDataSync();
  });
}

int IOManager::FStat(int fd, struct stat *stat_buffer) {
  return CallWithContext(fd, [stat_buffer](std::shared_ptr<IOContext> context) {
    return context->FStat(stat_buffer);
  });
}

ssize_t IOManager::FGetXattr(int fd, const char *name, void *value,
                             size_t size) {
  return CallWithContext(
      fd, [name, value, size](std::shared_ptr<IOContext> context) {
        return context->FGetXattr(name, value, size);
      });
}

int IOManager::FSetXattr(int fd, const char *name, const void *value,
                         size_t size, int flags) {
  return CallWithContext(
      fd, [name, value, size, flags](std::shared_ptr<IOContext> context) {
        return context->FSetXattr(name, value, size, flags);
      });
}

ssize_t IOManager::FListXattr(int fd, char *list, size_t size) {
  return CallWithContext(fd, [list, size](std::shared_ptr<IOContext> context) {
    return context->FListXattr(list, size);
  });
}

int IOManager::FStatFs(int fd, struct statfs *statfs_buffer) {
  return CallWithContext(fd,
                         [statfs_buffer](std::shared_ptr<IOContext> context) {
                           return context->FStatFs(statfs_buffer);
                         });
}

int IOManager::Isatty(int fd) {
  return CallWithContext(
      fd, [](std::shared_ptr<IOContext> context) { return context->Isatty(); });
}

int IOManager::FLock(int fd, int operation) {
  return CallWithContext(fd, [operation](std::shared_ptr<IOContext> context) {
    return context->FLock(operation);
  });
}

int IOManager::Ioctl(int fd, int request, void *argp) {
  return CallWithContext(fd,
                         [request, argp](std::shared_ptr<IOContext> context) {
                           return context->Ioctl(request, argp);
                         });
}

int IOManager::Mkdir(const char *path, mode_t mode) {
  return CallWithHandler(
      path, [mode](VirtualPathHandler *handler, const char *canonical_path) {
        return handler->Mkdir(canonical_path, mode);
      });
}

int IOManager::RmDir(const char *pathname) {
  return CallWithHandler(
      pathname, [](VirtualPathHandler *handler, const char *canonical_path) {
        return handler->RmDir(canonical_path);
      });
}

int IOManager::Rename(const char *oldpath, const char *newpath) {
  return CallWithHandler(
      oldpath, newpath,
      [](VirtualPathHandler *handler, const char *canonical_oldpath,
         const char *canonical_newpath) {
        return handler->Rename(canonical_oldpath, canonical_newpath);
      });
}

int IOManager::Utime(const char *filename, const struct utimbuf *times) {
  return CallWithHandler(filename, [times](VirtualPathHandler *handler,
                                           const char *canonical_path) {
    return handler->Utime(canonical_path, times);
  });
}

int IOManager::Utimes(const char *filename, const struct timeval times[2]) {
  return CallWithHandler(filename, [times](VirtualPathHandler *handler,
                                           const char *canonical_path) {
    return handler->Utimes(canonical_path, times);
  });
}

ssize_t IOManager::Writev(int fd, const struct iovec *iov, int iovcnt) {
  return CallWithContext(fd, [iov, iovcnt](std::shared_ptr<IOContext> context) {
    return context->Writev(iov, iovcnt);
  });
}

ssize_t IOManager::Readv(int fd, const struct iovec *iov, int iovcnt) {
  return CallWithContext(fd, [iov, iovcnt](std::shared_ptr<IOContext> context) {
    return context->Readv(iov, iovcnt);
  });
}

ssize_t IOManager::PRead(int fd, void *buf, size_t count, off_t offset) {
  return CallWithContext(
      fd, [buf, count, offset](std::shared_ptr<IOContext> context) {
        return context->PRead(buf, count, offset);
      });
}

mode_t IOManager::Umask(mode_t mask) { return enc_untrusted_umask(mask); }

int IOManager::GetRLimit(int resource, struct rlimit *rlim) {
  if (!rlim) {
    errno = EFAULT;
    return -1;
  }
  switch (resource) {
    case RLIMIT_NOFILE: {
      absl::ReaderMutexLock lock(&fd_table_lock_);
      rlim->rlim_cur = fd_table_.get_maximum_fd_soft_limit();
      rlim->rlim_max = fd_table_.get_maximum_fd_hard_limit();
      return 0;
    }
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
  if (rlim->rlim_cur > rlim->rlim_max) {
    errno = EINVAL;
    return -1;
  }
  switch (resource) {
    case RLIMIT_NOFILE: {
      absl::WriterMutexLock lock(&fd_table_lock_);
      if (!fd_table_.SetFileDescriptorLimits(rlim)) {
        return -1;
      }
      return 0;
    }
    default:
      errno = ENOSYS;
      return -1;
  }
}

int IOManager::SetSockOpt(int sockfd, int level, int option_name,
                          const void *option_value, socklen_t option_len) {
  return CallWithContext(sockfd, [level, option_name, option_value, option_len](
                                     std::shared_ptr<IOContext> context) {
    return context->SetSockOpt(level, option_name, option_value, option_len);
  });
}

int IOManager::Connect(int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {
  return CallWithContext(sockfd,
                         [addr, addrlen](std::shared_ptr<IOContext> context) {
                           return context->Connect(addr, addrlen);
                         });
}

int IOManager::Shutdown(int sockfd, int how) {
  return CallWithContext(sockfd, [how](std::shared_ptr<IOContext> context) {
    return context->Shutdown(how);
  });
}

ssize_t IOManager::Send(int sockfd, const void *buf, size_t len, int flags) {
  return CallWithContext(sockfd,
                         [buf, len, flags](std::shared_ptr<IOContext> context) {
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
  return CallWithContext(sockfd, [level, optname, optval,
                                  optlen](std::shared_ptr<IOContext> context) {
    return context->GetSockOpt(level, optname, optval, optlen);
  });
}

int IOManager::Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int ret = CallWithContext(
      sockfd, [addr, addrlen](std::shared_ptr<IOContext> context) {
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
  return CallWithContext(sockfd,
                         [addr, addrlen](std::shared_ptr<IOContext> context) {
                           return context->Bind(addr, addrlen);
                         });
}

int IOManager::Listen(int sockfd, int backlog) {
  return CallWithContext(sockfd, [backlog](std::shared_ptr<IOContext> context) {
    return context->Listen(backlog);
  });
}

ssize_t IOManager::SendMsg(int sockfd, const struct msghdr *msg, int flags) {
  return CallWithContext(sockfd,
                         [msg, flags](std::shared_ptr<IOContext> context) {
                           return context->SendMsg(msg, flags);
                         });
}

ssize_t IOManager::RecvMsg(int sockfd, struct msghdr *msg, int flags) {
  return CallWithContext(sockfd,
                         [msg, flags](std::shared_ptr<IOContext> context) {
                           return context->RecvMsg(msg, flags);
                         });
}

int IOManager::GetSockName(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen) {
  return CallWithContext(sockfd,
                         [addr, addrlen](std::shared_ptr<IOContext> context) {
                           return context->GetSockName(addr, addrlen);
                         });
}

int IOManager::GetPeerName(int sockfd, struct sockaddr *addr,
                           socklen_t *addrlen) {
  return CallWithContext(sockfd,
                         [addr, addrlen](std::shared_ptr<IOContext> context) {
                           return context->GetPeerName(addr, addrlen);
                         });
}

ssize_t IOManager::RecvFrom(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr *src_addr, socklen_t *addrlen) {
  return CallWithContext(sockfd, [buf, len, flags, src_addr,
                                  addrlen](std::shared_ptr<IOContext> context) {
    return context->RecvFrom(buf, len, flags, src_addr, addrlen);
  });
}

int IOManager::RegisterHostFileDescriptor(int host_fd) {
  absl::WriterMutexLock lock(&fd_table_lock_);
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
