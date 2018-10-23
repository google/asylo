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

#ifndef ASYLO_PLATFORM_POSIX_IO_IO_MANAGER_H_
#define ASYLO_PLATFORM_POSIX_IO_IO_MANAGER_H_

#include <errno.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <poll.h>
#include <stdint.h>
#include <atomic>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <queue>
#include <type_traits>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "asylo/platform/storage/secure/enclave_storage_secure.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace io {

// The IOManager implements a virtual filesystem abstraction and maintains a
// mapping from "enclave file descriptors" to IOContext objects.
class IOManager {
 public:
  // The maximum number of virtual file descriptors which may be open at any one
  // time.
  static const constexpr int kMaxOpenFiles = 1024;

  // An IOContext object represents an abstract I/O stream. Different concrete
  // implementations might wrap a native file descriptor on the host, a virtual
  // device like "/dev/urandom" backed by software, or a secure stream with
  // transparent inline encryption.
  class IOContext {
   public:
    IOContext() : fd_reference_(0){}

    virtual ~IOContext() = default;

   protected:
    // Implements IOManager::Read.
    virtual ssize_t Read(void *buf, size_t count) = 0;

    // Implements IOManager::Write.
    virtual ssize_t Write(const void *buf, size_t count) = 0;

    // Implements IOManager::Close.
    virtual int Close() = 0;

    // Implements IOManager::LSeek.
    virtual int LSeek(off_t offset, int whence) {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::Fcntl
    virtual int FCntl(int cmd, int64_t arg) {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::FSync.
    virtual int FSync() {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::FStat.
    virtual int FStat(struct stat *st) {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::Isatty.
    virtual int Isatty() {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::FLock.
    virtual int FLock(int operation) {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::Ioctl.
    virtual int Ioctl(int request, void *argp) {
      errno = ENOSYS;
      return -1;
    }

    // Implements IOManager::Writev.
    virtual ssize_t Writev(const struct iovec *iov, int iovcnt) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t Readv(const struct iovec *iov, int iovcnt) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FTruncate(off_t length) {
      errno = ENOSYS;
      return -1;
    }

    // Implements setsockopt.
    virtual int SetSockOpt(int level, int option_name, const void *option_value,
                           socklen_t option_len) {
      errno = ENOSYS;
      return -1;
    }

    // Implements connect.
    virtual int Connect(const struct sockaddr *addr, socklen_t addrlen) {
      errno = ENOSYS;
      return -1;
    }

    // Implements shutdown.
    virtual int Shutdown(int how) {
      errno = ENOSYS;
      return -1;
    }

    // Implements send.
    virtual ssize_t Send(const void *buf, size_t len, int flags) {
      errno = ENOSYS;
      return -1;
    }

    // Implements getsockopt.
    virtual int GetSockOpt(int level, int optname, void *optval,
                           socklen_t *optlen) {
      errno = ENOSYS;
      return -1;
    }

    // Implements accept.
    virtual int Accept(struct sockaddr *addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    // Implements bind.
    virtual int Bind(const struct sockaddr *addr, socklen_t addrlen) {
      errno = ENOSYS;
      return -1;
    }

    // Implements listen.
    virtual int Listen(int backlog) {
      errno = ENOSYS;
      return -1;
    }

    // Implements sendmsg.
    virtual ssize_t SendMsg(const struct msghdr *msg, int flags) {
      errno = ENOSYS;
      return -1;
    }

    // Implements recvmsg.
    virtual ssize_t RecvMsg(struct msghdr *msg, int flags) {
      errno = ENOSYS;
      return -1;
    }

    // Implements getsockname.
    virtual int GetSockName(struct sockaddr *addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    // Implements getpeername.
    virtual int GetPeerName(struct sockaddr *addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    // Implements epoll_ctl.
    virtual int EpollCtl(int op, int hostfd, struct epoll_event *event) {
      // EINVAL since file descriptors do not by default support epoll behavior.
      errno = EINVAL;
      return -1;
    }

    // Implements epoll_wait.
    virtual int EpollWait(struct epoll_event *events, int maxevents,
                          int timeout) {
      // EINVAL since file descriptors do not by defualt support epoll behavior.
      errno = EINVAL;
      return -1;
    }

    // Implements inotify_add_watch.
    virtual int InotifyAddWatch(const char *pathname, uint32_t mask) {
      errno = ENOSYS;
      return -1;
    }

    // Implements inotify_rm_watch.
    virtual int InotifyRmWatch(int wd) {
      errno = ENOSYS;
      return -1;
    }

    // Implements recvfrom.
    virtual ssize_t RecvFrom(void *buf, size_t len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }
    virtual int GetHostFileDescriptor() { return -1; }

    void IncrementFdReference() { fd_reference_++; }

    void DecrementFdReference() { fd_reference_--; }

    bool IsNoFdReference() { return fd_reference_ == 0; }

   private:
    friend class IOManager;

    // Number of file descriptors that refer to the IOContext.
    std::atomic<int> fd_reference_;
  };

  // A VirtualPathHandler maps file paths to appropriate behavior
  class VirtualPathHandler {
   public:
    virtual ~VirtualPathHandler() = default;

   protected:
    // Creates an IOContext object that will handle IO to the opened path
    virtual std::unique_ptr<IOContext> Open(const char *path, int flags,
                                            mode_t mode) = 0;

    virtual int Chown(const char *path, uid_t owner, gid_t group) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Link(const char *existing, const char *new_link) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t ReadLink(const char *path_name, char *buf, size_t bufsize) {
      errno = ENOSYS;
      return -1;
    }

    virtual int SymLink(const char *path1, const char *path2) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Stat(const char *pathname, struct stat *stat_buffer) {
      errno = ENOSYS;
      return -1;
    }

    virtual int LStat(const char *pathname, struct stat *stat_buffer) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Mkdir(const char *path, mode_t mode) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Unlink(const char *pathname) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Access(const char *path, int mode) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Truncate(const char *path, off_t length) {
      errno = ENOSYS;
      return -1;
    }

    virtual int ChMod(const char *pathname, mode_t mode) {
      errno = ENOSYS;
      return -1;
    }

   private:
    friend class IOManager;
  };

  // A table of virtual file descriptors managed by the IOManager.
  // This class is not thread safe. IOManager is responsible for locking the
  // access to objects of this class.
  class FileDescriptorTable {
   public:
    FileDescriptorTable();

    // Returns the IOContext associated with a file descriptor, or nullptr if
    // no such context exists.
    std::shared_ptr<IOContext> Get(int fd);

    // Removes an entry from the table, destroying the associated IOContext if
    // this is the last reference to the IOContext, and returns the file
    // descriptor to the free list.
    void Delete(int fd);

    // Returns true if a specified file descriptor is available.
    bool IsFileDescriptorUnused(int fd);

    // Inserts an I/O context into the table, assigning it the next available
    // file descriptor value and taking ownership of the pointer. Returns the
    // newly assigned fd.
    //
    // If the file descriptor table is full and the context can not be inserted,
    // returns -1 and does not take ownership of the passed context.
    int Insert(IOContext *context);

    // Creates a copy of |oldfd| using the next available file descriptor value
    // greater than or equal to |startfd|.
    // The two file descriptors will reference the same I/O context. Returns the
    // new file descriptor on success, returns -1 if |oldfd| is not valid or no
    // file descriptor is available.
    int CopyFileDescriptor(int oldfd, int startfd);

    // Creates a copy of |oldfd| using |newfd| for the new descriptor. The two
    // file descriptors will reference the same I/O context. Returns |newfd| on
    // success, returns -1 if either |oldfd| or |newfd| is not valid, or |newfd|
    // is already used.
    int CopyFileDescriptorToSpecifiedTarget(int oldfd, int newfd);

    bool SetFileDescriptorLimits(const struct rlimit *rlim);

    int get_maximum_fd_soft_limit();

    int get_maximum_fd_hard_limit();

   private:
    // Returns whether |fd| is in expected range.
    bool IsFileDescriptorValid(int fd);

    // Returns current highest file descriptor number. Returns -1 if no file
    // descriptors are used.
    int GetHighestFileDescriptorUsed();

    // Returns the lowest available file descriptor greater than or equal to
    // |startfd|. Returns -1 if there is no file descriptor available.
    int GetNextFreeFileDescriptor(int startfd);

    std::array<std::shared_ptr<IOContext>, kMaxOpenFiles> fd_table_;

    // The maximum file descriptor number allowed.
    int maximum_fd_soft_limit;

    // The ceiling for |maximum_fd_soft_limit|.
    int maximum_fd_hard_limit;
  };

  // Accessor to the singleton instance.
  static IOManager &GetInstance() {
    static IOManager *instance = new IOManager;
    return *instance;
  }

  // Returns 0 if |path| can be opened, otherwise -1.
  int Access(const char *path, int mode);

  // Change owner and group of a file. Returns 0 if completed successfully,
  // otherwise returns -1.
  int Chown(const char *path, uid_t owner, gid_t group);

  // Creates a hard link to an existing file. Returns 0 on success, otherwise
  // returns -1.
  int Link(const char *from, const char *to);

  // Places the contents of the symbolic link |path| in the buffer |buf|.
  // Returns the number of bytes placed in buf on success, otherwise returns -1.
  ssize_t ReadLink(const char *path, char *buf, size_t bufsize);

  // Creates a symbolic link |to| which contains the string |from|. Returns 0 on
  // success, otherwise returns -1.
  int SymLink(const char *from, const char *to);

  // Returns information about a file in the buffer pointed to by |stat_buffer|.
  // Returns 0 on success, otherwise returns -1. If |pathname| is a symlink,
  // returns information about the target it points to.
  int Stat(const char *pathname, struct stat *stat_buffer);

  // Returns information about a file in the buffer pointed to by |stat_buffer|.
  // Returns 0 on success, otherwise returns -1. Unlike Stat, if |pathname| is a
  // symlink, returns information about the link itself, rather than the target
  // it points to.
  int LStat(const char *pathname, struct stat *stat_buffer);

  // Provides a canonicalized absolute pathname that resolves symbolic links.
  // Returns |resolved_path| on success, nullptr on failure.
  char *RealPath(const char *path, char *resolved_path);

  // Opens |path|, returning an enclave file descriptor or -1 on failure.
  int Open(const char *path, int flags, mode_t mode);

  // Creates a copy of the file descriptor |oldfd| using the next available file
  // descriptor. Returns the new file descriptors on success, and -1 on error.
  int Dup(int oldfd) LOCKS_EXCLUDED(fd_table_lock_);

  // Creates a copy of the file descriptor |oldfd| using the file descriptor
  // specified by |newfd|. Returns the new file descriptor on success, and -1 on
  // error.
  int Dup2(int oldfd, int newfd) LOCKS_EXCLUDED(fd_table_lock_);

  // Creates a pipe. The array |pipefd| is used to return two file descriptors
  // referring to the ends of the pipe. |pipefd[0]| refers to the read end while
  // |pipefd[1]| refers to the write end.
  int Pipe(int pipefd[2]);

  // Reads up to |count| bytes from the stream into |buf|, returning the number
  // of bytes read on success or -1 on error.
  int Read(int fd, char *buf, size_t count);

  // Writes up to |count| bytes from to |fd| from |buf|, returning the number of
  // bytes written on success or -1 on error.
  int Write(int fd, const char *buf, size_t count);

  // Closes and finalizes the stream, returning 0 on success or -1 on error.
  int Close(int fd) LOCKS_EXCLUDED(fd_table_lock_);

  // Implements lseek(2).
  int LSeek(int fd, off_t offset, int whence);

  // Implements fcntl(2).
  int FCntl(int fd, int cmd, int64_t arg);

  // Implements fsync(2).
  int FSync(int fd);

  // Implements ioctl(2).
  int Ioctl(int fd, int request, void *argp);

  // Implements fstat(2).
  int FStat(int fd, struct stat *stat_buffer);

  // Implements isatty(3).
  int Isatty(int fd);

  // Implements flock(2).
  int FLock(int fd, int operation);

  // Implements unlink(2).
  int Unlink(const char *pathname);

  // Implements truncate(2).
  int Truncate(const char *path, off_t length);

  // Implements ftruncate(2).
  int FTruncate(int fd, off_t length);

  // Implements select(2).
  int Select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
             struct timeval *timeout);

  // Implements poll(2).
  int Poll(struct pollfd *fds, nfds_t nfds, int timeout)
      LOCKS_EXCLUDED(fd_table_lock_);

  // Implements epoll_create(2).
  int EpollCreate(int size) LOCKS_EXCLUDED(fd_table_lock_);

  // Implements epoll_ctl(2);
  int EpollCtl(int epfd, int op, int fd, struct epoll_event *event);

  // Implements epoll_wait(2);
  int EpollWait(int epfd, struct epoll_event *events, int maxevents,
                int timeout);

  // Implements mkdir(2).
  int Mkdir(const char *pathname, mode_t mode);

  // Implements writev(2).
  ssize_t Writev(int fd, const struct iovec *iov, int iovcnt);

  // Implements readv(2).
  ssize_t Readv(int fd, const struct iovec *iov, int iovcnt);

  // Implements umask(2).
  mode_t Umask(mode_t mask);

  // Implements chmod(2).
  int ChMod(const char *pathname, mode_t mode);

  // Implements getrlimit(2).
  int GetRLimit(int resource, struct rlimit *rlim)
      LOCKS_EXCLUDED(fd_table_lock_);

  // Implements setrlimit(2).
  int SetRLimit(int resource, const struct rlimit *rlim)
      LOCKS_EXCLUDED(fd_table_lock_);

  // Implements setsockopt(2).
  int SetSockOpt(int sockfd, int level, int option_name,
                 const void *option_value, socklen_t option_len);

  // Implements connect(2).
  int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

  // Implements shutdown(2).
  int Shutdown(int sockfd, int how);

  // Implements send(2).
  ssize_t Send(int sockfd, const void *buf, size_t len, int flags);

  // Implements getsockopt(2).
  int GetSockOpt(int sockfd, int level, int optname, void *optval,
                 socklen_t *optlen);

  // Implements accept(2).
  int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

  // Implements bind(2).
  int Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

  // Implements listen(2).
  int Listen(int sockfd, int backlog);

  // Implements sendmsg(2).
  ssize_t SendMsg(int sockfd, const struct msghdr *msg, int flags);

  // Implements recvmsg(2).
  ssize_t RecvMsg(int sockfd, struct msghdr *msg, int flags);

  // Implements getsockname(2).
  int GetSockName(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

  // Implements getpeername(2).
  int GetPeerName(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

  // Implements socket(2).
  int Socket(int domain, int type, int protocol);

  // Implements eventfd(2).
  int EventFd(unsigned int initval, int flags) LOCKS_EXCLUDED(fd_table_lock_);

    // Implements inotify_init(2).
  int InotifyInit(bool non_block) LOCKS_EXCLUDED(fd_table_lock_);

  // Implements inotify_add_watch(2).
  int InotifyAddWatch(int fd, const char *pathname, uint32_t mask);

  // Implements inotify_rm_watch(2).
  int InotifyRmWatch(int fd, int wd);

  // Implements recvfrom(2).
  ssize_t RecvFrom(int sockfd, void *buf, size_t len, int flags,
                   struct sockaddr *src_addr, socklen_t *addrlen);
  // Binds an enclave file descriptor to a host file descriptor, returning an
  // enclave file descriptor which will delegate all I/O operations to the host
  // operating system.
  int RegisterHostFileDescriptor(int host_fd) LOCKS_EXCLUDED(fd_table_lock_);

  // Registers the handler responsible for a given path prefix.
  // When processing a path, the handler with the longest prefix shared with the
  // path will be chosen.  Prefixes are considered shared only on whole
  // directory increments.
  // The provided prefix must not end in a trailing /.
  // Registering already registered prefixes will replace the old handler.
  // "Overlapping" prefixes are allowed. e.g. /foo/ and /foo/bar/
  bool RegisterVirtualPathHandler(const std::string &path_prefix,
                                  std::unique_ptr<VirtualPathHandler> handler);

  // Deregisters the handler responsible for a given path prefix
  void DeregisterVirtualPathHandler(const std::string &path_prefix);

  Status SetCurrentWorkingDirectory(absl::string_view path);
  std::string GetCurrentWorkingDirectory() const;

 private:
  IOManager() {}
  IOManager(IOManager const &) = delete;
  void operator=(IOManager const &) = delete;

  // Converts a (possibly user-provided) path and converts it to a canonical
  // representation.  This includes current working directory handling for
  // relative paths and path normalization.
  StatusOr<std::string> CanonicalizePath(absl::string_view path) const;

  // Closes a file descriptor by removing it from |fd_table_|, and closing the
  // corresponding host file descriptor if this is the last reference to it.
  // This method does not obtain a locker. Caller of this method is responsible
  // for obtaining |fd_table_lock_|.
  int CloseFileDescriptor(int fd) EXCLUSIVE_LOCKS_REQUIRED(fd_table_lock_);

  // Fetches the VirtualFileHandler associated with a given path, or
  // nullptr if no entry is found.
  VirtualPathHandler *HandlerForPath(absl::string_view path) const;

  // Locks the mutex corresponding to |fd| and performs thread safe action.
  template <typename IOAction, typename ReturnType = typename std::result_of<
                                   IOAction(std::shared_ptr<IOContext>)>::type>
  ReturnType CallWithContext(int fd, IOAction action)
      LOCKS_EXCLUDED(fd_table_lock_);

  // Looks up the appropriate VirtualPathHandler and calls the given function on
  // it.  Errors related to path resolution and handler lookups are handled.
  // This is the single path variant.
  template <typename IOAction,
            typename ReturnType = typename std::result_of<
                IOAction(IOManager::VirtualPathHandler *, const char *)>::type>
  ReturnType CallWithHandler(const char *path, IOAction action);

  // Looks up the appropriate VirtualPathHandler and calls the given function on
  // it.  Errors related to path resolution and handler lookups are handled.
  // This is the double path variant.  Both paths must resolve to the same
  // handler.
  template <typename IOAction,
            typename ReturnType = typename std::result_of<IOAction(
                VirtualPathHandler *, const char *, const char *)>::type>
  ReturnType CallWithHandler(const char *path1, const char *path2,
                             IOAction action);

  // A map from path prefix to VirtualPathHandler.
  std::map<std::string, std::unique_ptr<VirtualPathHandler>> prefix_to_handler_;

  FileDescriptorTable fd_table_;

  // A mutex that locks the fd_table_.
  absl::Mutex fd_table_lock_;

  std::string current_working_directory_;
};

}  // namespace io
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_IO_IO_MANAGER_H_
