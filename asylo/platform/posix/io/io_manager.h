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

#include <poll.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <utime.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <queue>
#include <type_traits>

#include "absl/base/thread_annotations.h"
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
    virtual ~IOContext() = default;

   protected:
    virtual ssize_t Read(void *buf, size_t count) = 0;

    virtual ssize_t Write(const void *buf, size_t count) = 0;

    virtual int Close() = 0;

    virtual int LSeek(off_t offset, int whence) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FCntl(int cmd, int64_t arg) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FSync() {
      errno = ENOSYS;
      return -1;
    }

    virtual int FDataSync() { return FSync(); }

    virtual int FChOwn(uid_t owner, gid_t group) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FStat(struct stat *st) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FStatFs(struct statfs *statfs_buffer) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Isatty() {
      errno = ENOSYS;
      return -1;
    }

    virtual int FLock(int operation) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FChMod(mode_t mode) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Ioctl(int request, void *argp) {
      errno = ENOSYS;
      return -1;
    }

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

    virtual ssize_t PRead(void *buf, size_t count, off_t offset) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t FGetXattr(const char *name, void *value, size_t size) {
      errno = ENOSYS;
      return -1;
    }

    virtual int FSetXattr(const char *name, const void *value, size_t size,
                          int flags) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t FListXattr(char *list, size_t size) {
      errno = ENOSYS;
      return -1;
    }

    virtual int SetSockOpt(int level, int option_name, const void *option_value,
                           socklen_t option_len) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Connect(const struct sockaddr *addr, socklen_t addrlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Shutdown(int how) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t Send(const void *buf, size_t len, int flags) {
      errno = ENOSYS;
      return -1;
    }

    virtual int GetSockOpt(int level, int optname, void *optval,
                           socklen_t *optlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Accept(struct sockaddr *addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Bind(const struct sockaddr *addr, socklen_t addrlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Listen(int backlog) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t SendMsg(const struct msghdr *msg, int flags) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t RecvMsg(struct msghdr *msg, int flags) {
      errno = ENOSYS;
      return -1;
    }

    virtual int GetSockName(struct sockaddr *addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int GetPeerName(struct sockaddr *addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int EpollCtl(int op, int hostfd, struct epoll_event *event) {
      // EINVAL since file descriptors do not by default support epoll behavior.
      errno = EINVAL;
      return -1;
    }

    virtual int EpollWait(struct epoll_event *events, int maxevents,
                          int timeout) {
      // EINVAL since file descriptors do not by defualt support epoll behavior.
      errno = EINVAL;
      return -1;
    }

    virtual int InotifyAddWatch(const char *pathname, uint32_t mask) {
      errno = ENOSYS;
      return -1;
    }

    virtual int InotifyRmWatch(int wd) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t RecvFrom(void *buf, size_t len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen) {
      errno = ENOSYS;
      return -1;
    }

    virtual int GetHostFileDescriptor() { return -1; }

   private:
    friend class IOManager;
    friend class NativePathHandler;
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

    virtual int StatFs(const char *pathname, struct statfs *statfs_buffer) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Mkdir(const char *path, mode_t mode) {
      errno = ENOSYS;
      return -1;
    }

    virtual int RmDir(const char *pathname) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Rename(const char *oldpath, const char *newpath) {
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

    virtual int Utime(const char *filename, const struct utimbuf *times) {
      errno = ENOSYS;
      return -1;
    }

    virtual int Utimes(const char *filename, const struct timeval times[2]) {
      errno = ENOSYS;
      return -1;
    }

    virtual int InotifyAddWatch(std::shared_ptr<IOContext> context,
                                const char *pathname, uint32_t mask) {
      errno = ENOENT;
      return -1;
    }

    virtual ssize_t GetXattr(const char *path, const char *name, void *value,
                             size_t size) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t LGetXattr(const char *path, const char *name, void *value,
                              size_t size) {
      errno = ENOSYS;
      return -1;
    }

    virtual int SetXattr(const char *path, const char *name, const void *value,
                         size_t size, int flags) {
      errno = ENOSYS;
      return -1;
    }

    virtual int LSetXattr(const char *path, const char *name, const void *value,
                          size_t size, int flags) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t ListXattr(const char *path, char *list, size_t size) {
      errno = ENOSYS;
      return -1;
    }

    virtual ssize_t LListXattr(const char *path, char *list, size_t size) {
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
    // descriptor to the free list. If close() is called on the host and that
    // call fails, returns -1; otherwise, returns 0.
    int Delete(int fd);

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
    // A wrapper around IOContext that ensures that the IOContext is destroyed
    // when there are no longer any references to it.
    //
    // A shared_ptr<AutoCloseIOContext> represents a file descriptor referring
    // to a backing IOContext, whereas a shared_ptr<IOContext> keeps the
    // IOContext alive, even if there are no file descriptors referencing it.
    class AutoCloseIOContext {
     public:
      explicit AutoCloseIOContext(IOContext *context)
          : close_result_(nullptr), context_(context) {}

      ~AutoCloseIOContext() {
        if (context_->Close() == -1) {
          int *close_result = close_result_.load();
          if (close_result) {
            *close_result = -1;
          }
        }
      }

      std::shared_ptr<IOContext> Get() { return context_; }

      // Indicates that if the Close() call in the destructor fails, then -1
      // should be written to |close_result|. If called multiple times, only the
      // most recent |close_result| pointer is used.
      void WriteCloseResultTo(int *close_result) {
        close_result_.store(close_result);
      }

     private:
      // Where to write the result of the Close() call in the destructor if it
      // fails. May be nullptr, in which case any Close() failures are silent.
      std::atomic<int *> close_result_;

      // The IOContext to wrap. A shared_ptr is used to ensure that calls using
      // the context object don't end up with dangling pointers if the wrapping
      // AutoCloseIOContext gets destroyed.
      std::shared_ptr<IOContext> context_;
    };

    // Returns whether |fd| is in expected range.
    bool IsFileDescriptorValid(int fd);

    // Returns current highest file descriptor number. Returns -1 if no file
    // descriptors are used.
    int GetHighestFileDescriptorUsed();

    // Returns the lowest available file descriptor greater than or equal to
    // |startfd|. Returns -1 if there is no file descriptor available.
    int GetNextFreeFileDescriptor(int startfd);

    std::array<std::shared_ptr<AutoCloseIOContext>, kMaxOpenFiles> fd_table_;

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
  virtual int Access(const char *path, int mode);

  // Change owner and group of a file. Returns 0 if completed successfully,
  // otherwise returns -1.
  virtual int Chown(const char *path, uid_t owner, gid_t group);

  // Creates a hard link to an existing file. Returns 0 on success, otherwise
  // returns -1.
  virtual int Link(const char *from, const char *to);

  // Places the contents of the symbolic link |path| in the buffer |buf|.
  // Returns the number of bytes placed in buf on success, otherwise returns -1.
  virtual ssize_t ReadLink(const char *path, char *buf, size_t bufsize);

  // Creates a symbolic link |to| which contains the string |from|. Returns 0 on
  // success, otherwise returns -1.
  virtual int SymLink(const char *from, const char *to);

  // Returns information about a file in the buffer pointed to by |stat_buffer|.
  // Returns 0 on success, otherwise returns -1. If |pathname| is a symlink,
  // returns information about the target it points to.
  virtual int Stat(const char *pathname, struct stat *stat_buffer);

  // Returns information about a file in the buffer pointed to by |stat_buffer|.
  // Returns 0 on success, otherwise returns -1. Unlike Stat, if |pathname| is a
  // symlink, returns information about the link itself, rather than the target
  // it points to.
  virtual int LStat(const char *pathname, struct stat *stat_buffer);

  // Provides a canonicalized absolute pathname that resolves symbolic links.
  // Returns |resolved_path| on success, nullptr on failure.
  char *RealPath(const char *path, char *resolved_path);

  // Opens |path|, returning an enclave file descriptor or -1 on failure.
  virtual int Open(const char *path, int flags, mode_t mode);

  // Creates a copy of the file descriptor |oldfd| using the next available file
  // descriptor. Returns the new file descriptors on success, and -1 on error.
  virtual int Dup(int oldfd) ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Creates a copy of the file descriptor |oldfd| using the file descriptor
  // specified by |newfd|. Returns the new file descriptor on success, and -1 on
  // error.
  virtual int Dup2(int oldfd, int newfd) ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Creates a pipe with the given |flags|, which must be a bitwise-or of any
  // combination of O_CLOEXEC, O_DIRECT, and O_NONBLOCK. The array |pipefd| is
  // used to return two file descriptors referring to the ends of the pipe.
  // |pipefd[0]| refers to the read end while |pipefd[1]| refers to the write
  // end.
  virtual int Pipe(int pipefd[2], int flags);

  // Reads up to |count| bytes from the stream into |buf|, returning the number
  // of bytes read on success or -1 on error.
  virtual int Read(int fd, char *buf, size_t count);

  // Writes up to |count| bytes from to |fd| from |buf|, returning the number of
  // bytes written on success or -1 on error.
  virtual int Write(int fd, const char *buf, size_t count);

  // Closes and finalizes the stream, returning 0 on success or -1 on error.
  virtual int Close(int fd) ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements fchown(2).
  virtual int FChOwn(int fd, uid_t owner, gid_t group);

  // Implements lseek(2).
  virtual int LSeek(int fd, off_t offset, int whence);

  // Implements fchmod(2).
  virtual int FChMod(int fd, mode_t mode);

  // Implements fcntl(2).
  virtual int FCntl(int fd, int cmd, int64_t arg);

  // Implements fsync(2).
  virtual int FSync(int fd);

  // Implements fdatasync(2).
  virtual int FDataSync(int fd);

  // Implements ioctl(2).
  virtual int Ioctl(int fd, int request, void *argp);

  // Implements fstat(2).
  virtual int FStat(int fd, struct stat *stat_buffer);

  // Implements statfs(2).
  virtual int StatFs(const char *pathname, struct statfs *statfs_buffer);

  // Implements fstatfs(2).
  virtual int FStatFs(int fd, struct statfs *statfs_buffer);

  // Implements isatty(3).
  int Isatty(int fd);

  // Implements flock(2).
  virtual int FLock(int fd, int operation);

  // Implements unlink(2).
  virtual int Unlink(const char *pathname);

  // Implements truncate(2).
  virtual int Truncate(const char *path, off_t length);

  // Implements ftruncate(2).
  virtual int FTruncate(int fd, off_t length);

  // Implements select(2).
  virtual int Select(int nfds, fd_set *readfds, fd_set *writefds,
                     fd_set *exceptfds, struct timeval *timeout);

  // Implements poll(2).
  virtual int Poll(struct pollfd *fds, nfds_t nfds, int timeout)
      ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements epoll_create(2).
  virtual int EpollCreate(int size) ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements epoll_ctl(2);
  virtual int EpollCtl(int epfd, int op, int fd, struct epoll_event *event);

  // Implements epoll_wait(2);
  virtual int EpollWait(int epfd, struct epoll_event *events, int maxevents,
                        int timeout);

  // Implements mkdir(2).
  virtual int Mkdir(const char *pathname, mode_t mode);

  // Implements rmdir(2).
  virtual int RmDir(const char *pathname);

  // Implements rename(2).
  virtual int Rename(const char *oldpath, const char *newpath);

  // Implements writev(2).
  virtual ssize_t Writev(int fd, const struct iovec *iov, int iovcnt);

  // Implements readv(2).
  virtual ssize_t Readv(int fd, const struct iovec *iov, int iovcnt);

  // Implements pread(2).
  virtual ssize_t PRead(int fd, void *buf, size_t count, off_t offset);

  // Implements umask(2).
  virtual mode_t Umask(mode_t mask);

  // Implements chmod(2).
  virtual int ChMod(const char *pathname, mode_t mode);

  // Implements utime(2).
  virtual int Utime(const char *filename, const struct utimbuf *times);

  // Implements utimes(2).
  virtual int Utimes(const char *filename, const struct timeval times[2]);

  // Implements getrlimit(2).
  virtual int GetRLimit(int resource, struct rlimit *rlim)
      ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements setrlimit(2).
  virtual int SetRLimit(int resource, const struct rlimit *rlim)
      ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements getxattr(2).
  virtual ssize_t GetXattr(const char *path, const char *name, void *value,
                           size_t size);

  // Implements lgetxattr(2).
  virtual ssize_t LGetXattr(const char *path, const char *name, void *value,
                            size_t size);

  // Implements fgetxattr(2).
  virtual ssize_t FGetXattr(int fd, const char *name, void *value, size_t size);

  // Implements setxattr(2).
  virtual int SetXattr(const char *path, const char *name, const void *value,
                       size_t size, int flags);

  // Implements lsetxattr(2).
  virtual int LSetXattr(const char *path, const char *name, const void *value,
                        size_t size, int flags);

  // Implements fsetxattr(2).
  virtual int FSetXattr(int fd, const char *name, const void *value,
                        size_t size, int flags);

  // Implements listxattr(2).
  virtual ssize_t ListXattr(const char *path, char *list, size_t size);

  // Implements llistxattr(2).
  virtual ssize_t LListXattr(const char *path, char *list, size_t size);

  // Implements flistxattr(2).
  virtual ssize_t FListXattr(int fd, char *list, size_t size);

  // Implements setsockopt(2).
  virtual int SetSockOpt(int sockfd, int level, int option_name,
                         const void *option_value, socklen_t option_len);

  // Implements connect(2).
  virtual int Connect(int sockfd, const struct sockaddr *addr,
                      socklen_t addrlen);

  // Implements shutdown(2).
  virtual int Shutdown(int sockfd, int how);

  // Implements send(2).
  virtual ssize_t Send(int sockfd, const void *buf, size_t len, int flags);

  // Implements getsockopt(2).
  virtual int GetSockOpt(int sockfd, int level, int optname, void *optval,
                         socklen_t *optlen);

  // Implements accept(2).
  virtual int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

  // Implements bind(2).
  virtual int Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

  // Implements listen(2).
  virtual int Listen(int sockfd, int backlog);

  // Implements sendmsg(2).
  virtual ssize_t SendMsg(int sockfd, const struct msghdr *msg, int flags);

  // Implements recvmsg(2).
  virtual ssize_t RecvMsg(int sockfd, struct msghdr *msg, int flags);

  // Implements getsockname(2).
  virtual int GetSockName(int sockfd, struct sockaddr *addr,
                          socklen_t *addrlen);

  // Implements getpeername(2).
  virtual int GetPeerName(int sockfd, struct sockaddr *addr,
                          socklen_t *addrlen);

  // Implements socket(2).
  virtual int Socket(int domain, int type, int protocol);

  // Implements eventfd(2).
  virtual int EventFd(unsigned int initval, int flags)
      ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements inotify_init(2).
  virtual int InotifyInit(bool non_block) ABSL_LOCKS_EXCLUDED(fd_table_lock_);

  // Implements inotify_add_watch(2).
  virtual int InotifyAddWatch(int fd, const char *pathname, uint32_t mask);

  // Implements inotify_rm_watch(2).
  virtual int InotifyRmWatch(int fd, int wd);

  // Implements recvfrom(2).
  virtual ssize_t RecvFrom(int sockfd, void *buf, size_t len, int flags,
                           struct sockaddr *src_addr, socklen_t *addrlen);
  // Binds an enclave file descriptor to a host file descriptor, returning an
  // enclave file descriptor which will delegate all I/O operations to the host
  // operating system.
  int RegisterHostFileDescriptor(int host_fd)
      ABSL_LOCKS_EXCLUDED(fd_table_lock_);

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

 protected:
  IOManager() = default;

 private:
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
  int CloseFileDescriptor(int fd) ABSL_EXCLUSIVE_LOCKS_REQUIRED(fd_table_lock_);

  // Fetches the VirtualFileHandler associated with a given path, or
  // nullptr if no entry is found.
  VirtualPathHandler *HandlerForPath(absl::string_view path) const;

  // Locks the mutex corresponding to |fd| and performs thread safe action.
  template <typename IOAction, typename ReturnType = typename std::result_of<
                                   IOAction(std::shared_ptr<IOContext>)>::type>
  ReturnType CallWithContext(int fd, IOAction action)
      ABSL_LOCKS_EXCLUDED(fd_table_lock_);

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

