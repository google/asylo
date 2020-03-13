/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/platform/posix/syscall/enclave_syscall.h"

#include <cerrno>

#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/syscall/enclave_syscall_helper.h"
#include "asylo/platform/posix/syscall/signal_syscalls.h"
#include "asylo/platform/primitives/trusted_runtime.h"

#define MAX_SYSNO 335

namespace asylo {
namespace system_call {

bool direct_sysnos[MAX_SYSNO] = {false};

bool PopulateSysnoTable() {
  direct_sysnos[asylo::system_call::kSYS_getpid] = true;
  direct_sysnos[asylo::system_call::kSYS_getgid] = true;
  direct_sysnos[asylo::system_call::kSYS_getuid] = true;
  direct_sysnos[asylo::system_call::kSYS_getegid] = true;
  direct_sysnos[asylo::system_call::kSYS_geteuid] = true;
  direct_sysnos[asylo::system_call::kSYS_getppid] = true;
  direct_sysnos[asylo::system_call::kSYS_setsid] = true;
  direct_sysnos[asylo::system_call::kSYS_getitimer] = true;
  direct_sysnos[asylo::system_call::kSYS_setitimer] = true;
  direct_sysnos[asylo::system_call::kSYS_getrusage] = true;
  direct_sysnos[asylo::system_call::kSYS_gettimeofday] = true;
  direct_sysnos[asylo::system_call::kSYS_nanosleep] = true;
  direct_sysnos[asylo::system_call::kSYS_sched_getaffinity] = true;
  direct_sysnos[asylo::system_call::kSYS_sched_yield] = true;
  direct_sysnos[asylo::system_call::kSYS_syslog] = true;
  direct_sysnos[asylo::system_call::kSYS_times] = true;
  direct_sysnos[asylo::system_call::kSYS_uname] = true;

  return true;
}

int64_t EnclaveSyscallWithDeps(int sysno, uint64_t* args, size_t nargs,
                               EnclaveSyscallHelper* helper,
                               asylo::io::IOManager* io_manager) {
  static bool initialized = PopulateSysnoTable();

  if (!initialized) {
    errno = EAGAIN;
    return -1;
  }

  if (sysno >= MAX_SYSNO) {
    errno = EINVAL;
    return -1;
  }

  if (direct_sysnos[sysno]) {
    return helper->DispatchSyscall(sysno, args, nargs);
  }

  switch (sysno) {
    case asylo::system_call::kSYS_access:
      return io_manager->Access(reinterpret_cast<const char*>(args[0]),
                                args[1]);
    case asylo::system_call::kSYS_close:
      return io_manager->Close(args[0]);
    case asylo::system_call::kSYS_open:
      return io_manager->Open(reinterpret_cast<const char*>(args[0]), args[1],
                              args[2]);
    case asylo::system_call::kSYS_dup:
      return io_manager->Dup(args[0]);
    case asylo::system_call::kSYS_dup2:
      return io_manager->Dup2(args[0], args[1]);
    case asylo::system_call::kSYS_pipe:
      return io_manager->Pipe(reinterpret_cast<int*>(args[0]), 0);
    case asylo::system_call::kSYS_pipe2:
      return io_manager->Pipe(reinterpret_cast<int*>(args[0]), args[1]);
    case asylo::system_call::kSYS_select:
      return io_manager->Select(args[0], reinterpret_cast<fd_set*>(args[1]),
                                reinterpret_cast<fd_set*>(args[2]),
                                reinterpret_cast<fd_set*>(args[3]),
                                reinterpret_cast<timeval*>(args[4]));
    case asylo::system_call::kSYS_poll:
      return io_manager->Poll(reinterpret_cast<pollfd*>(args[0]), args[1],
                              args[2]);
    case asylo::system_call::kSYS_epoll_create:
      return io_manager->EpollCreate(args[0]);
    case asylo::system_call::kSYS_epoll_ctl:
      return io_manager->EpollCtl(args[0], args[1], args[2],
                                  reinterpret_cast<epoll_event*>(args[3]));
    case asylo::system_call::kSYS_epoll_wait:
      return io_manager->EpollWait(
          args[0], reinterpret_cast<epoll_event*>(args[1]), args[2], args[3]);
    case asylo::system_call::kSYS_eventfd:
      return io_manager->EventFd(args[0], 0);
    case asylo::system_call::kSYS_eventfd2:
      return io_manager->EventFd(args[0], args[1]);
    case asylo::system_call::kSYS_inotify_init:
      return io_manager->InotifyInit(false);
    case asylo::system_call::kSYS_inotify_init1:
      return io_manager->InotifyInit(args[0] & IN_NONBLOCK);
    case asylo::system_call::kSYS_inotify_add_watch:
      return io_manager->InotifyAddWatch(
          args[0], reinterpret_cast<const char*>(args[1]), args[2]);
    case asylo::system_call::kSYS_inotify_rm_watch:
      return io_manager->InotifyRmWatch(args[0], args[1]);
    case asylo::system_call::kSYS_read:
      return io_manager->Read(args[0], reinterpret_cast<char*>(args[1]),
                              args[2]);
    case asylo::system_call::kSYS_write:
      return io_manager->Write(args[0], reinterpret_cast<const char*>(args[1]),
                               args[2]);
    case asylo::system_call::kSYS_chown:
      return io_manager->Chown(reinterpret_cast<const char*>(args[0]), args[1],
                               args[2]);
    case asylo::system_call::kSYS_fchown:
      return io_manager->FChOwn(args[0], args[1], args[2]);
    case asylo::system_call::kSYS_link:
      return io_manager->Link(reinterpret_cast<const char*>(args[0]),
                              reinterpret_cast<const char*>(args[1]));
    case asylo::system_call::kSYS_unlink:
      return io_manager->Unlink(reinterpret_cast<const char*>(args[0]));
    case asylo::system_call::kSYS_readlink:
      return io_manager->ReadLink(reinterpret_cast<const char*>(args[0]),
                                  reinterpret_cast<char*>(args[1]), args[2]);
    case asylo::system_call::kSYS_symlink:
      return io_manager->SymLink(reinterpret_cast<const char*>(args[0]),
                                 reinterpret_cast<const char*>(args[1]));
    case asylo::system_call::kSYS_truncate:
      return io_manager->Truncate(reinterpret_cast<const char*>(args[0]),
                                  args[1]);
    case asylo::system_call::kSYS_ftruncate:
      return io_manager->FTruncate(args[0], args[1]);
    case asylo::system_call::kSYS_stat:
      return io_manager->Stat(reinterpret_cast<const char*>(args[0]),
                              reinterpret_cast<struct stat*>(args[1]));
    case asylo::system_call::kSYS_lstat:
      return io_manager->LStat(reinterpret_cast<const char*>(args[0]),
                               reinterpret_cast<struct stat*>(args[1]));
    case asylo::system_call::kSYS_statfs:
      return io_manager->StatFs(reinterpret_cast<const char*>(args[0]),
                                reinterpret_cast<struct statfs*>(args[1]));
    case asylo::system_call::kSYS_fstat:
      return io_manager->FStat(args[0],
                               reinterpret_cast<struct stat*>(args[1]));
    case asylo::system_call::kSYS_fstatfs:
      return io_manager->FStatFs(args[0],
                                 reinterpret_cast<struct statfs*>(args[1]));
    case asylo::system_call::kSYS_chmod:
      return io_manager->ChMod(reinterpret_cast<const char*>(args[0]), args[1]);
    case asylo::system_call::kSYS_fchmod:
      return io_manager->FChMod(args[0], args[1]);
    case asylo::system_call::kSYS_lseek:
      return io_manager->LSeek(args[0], args[1], args[2]);
    case asylo::system_call::kSYS_fcntl:
      return io_manager->FCntl(args[0], args[1], args[2]);
    case asylo::system_call::kSYS_fsync:
      return io_manager->FSync(args[0]);
    case asylo::system_call::kSYS_fdatasync:
      return io_manager->FDataSync(args[0]);
    case asylo::system_call::kSYS_flock:
      return io_manager->FLock(args[0], args[1]);
    case asylo::system_call::kSYS_ioctl:
      return io_manager->Ioctl(args[0], args[1],
                               reinterpret_cast<void*>(args[2]));
    case asylo::system_call::kSYS_mkdir:
      return io_manager->Mkdir(reinterpret_cast<const char*>(args[0]), args[1]);
    case asylo::system_call::kSYS_rmdir:
      return io_manager->RmDir(reinterpret_cast<const char*>(args[0]));
    case asylo::system_call::kSYS_rename:
      return io_manager->Rename(reinterpret_cast<const char*>(args[0]),
                                reinterpret_cast<const char*>(args[1]));
    case asylo::system_call::kSYS_utime:
      return io_manager->Utime(reinterpret_cast<const char*>(args[0]),
                               reinterpret_cast<const utimbuf*>(args[1]));
    case asylo::system_call::kSYS_utimes:
      return io_manager->Utimes(reinterpret_cast<const char*>(args[0]),
                                reinterpret_cast<const timeval*>(args[1]));
    case asylo::system_call::kSYS_writev:
      return io_manager->Writev(
          args[0], reinterpret_cast<const iovec*>(args[1]), args[2]);
    case asylo::system_call::kSYS_readv:
      return io_manager->Readv(args[0], reinterpret_cast<const iovec*>(args[1]),
                               args[2]);
    case asylo::system_call::kSYS_pread64:
      return io_manager->PRead(args[0], reinterpret_cast<void*>(args[1]),
                               args[2], args[3]);
    case asylo::system_call::kSYS_umask:
      return io_manager->Umask(args[0]);
    case asylo::system_call::kSYS_getrlimit:
      return io_manager->GetRLimit(args[0], reinterpret_cast<rlimit*>(args[1]));
    case asylo::system_call::kSYS_setrlimit:
      return io_manager->SetRLimit(args[0],
                                   reinterpret_cast<const rlimit*>(args[1]));
    case asylo::system_call::kSYS_setsockopt:
      return io_manager->SetSockOpt(args[0], args[1], args[2],
                                    reinterpret_cast<const void*>(args[3]),
                                    args[4]);
    case asylo::system_call::kSYS_connect:
      return io_manager->Connect(
          args[0], reinterpret_cast<const sockaddr*>(args[1]), args[2]);
    case asylo::system_call::kSYS_shutdown:
      return io_manager->Shutdown(args[0], args[1]);
    case asylo::system_call::kSYS_sendto:
      return io_manager->Send(args[0], reinterpret_cast<const void*>(args[1]),
                              args[2], args[3]);
    case asylo::system_call::kSYS_socket:
      return io_manager->Socket(args[0], args[1], args[2]);
    case asylo::system_call::kSYS_getsockopt:
      return io_manager->GetSockOpt(args[0], args[1], args[2],
                                    reinterpret_cast<void*>(args[3]),
                                    reinterpret_cast<socklen_t*>(args[4]));
    case asylo::system_call::kSYS_accept:
      return io_manager->Accept(args[0], reinterpret_cast<sockaddr*>(args[1]),
                                reinterpret_cast<socklen_t*>(args[2]));
    case asylo::system_call::kSYS_bind:
      return io_manager->Bind(
          args[0], reinterpret_cast<const sockaddr*>(args[1]), args[2]);
    case asylo::system_call::kSYS_listen:
      return io_manager->Listen(args[0], args[1]);
    case asylo::system_call::kSYS_sendmsg:
      return io_manager->SendMsg(
          args[0], reinterpret_cast<const msghdr*>(args[1]), args[2]);
    case asylo::system_call::kSYS_recvmsg:
      return io_manager->RecvMsg(args[0], reinterpret_cast<msghdr*>(args[1]),
                                 args[2]);
    case asylo::system_call::kSYS_getsockname:
      return io_manager->GetSockName(args[0],
                                     reinterpret_cast<sockaddr*>(args[1]),
                                     reinterpret_cast<socklen_t*>(args[2]));
    case asylo::system_call::kSYS_getpeername:
      return io_manager->GetPeerName(args[0],
                                     reinterpret_cast<sockaddr*>(args[1]),
                                     reinterpret_cast<socklen_t*>(args[2]));
    case asylo::system_call::kSYS_recvfrom:
      return io_manager->RecvFrom(args[0], reinterpret_cast<void*>(args[1]),
                                  args[2], args[3],
                                  reinterpret_cast<sockaddr*>(args[4]),
                                  reinterpret_cast<socklen_t*>(args[5]));
    case asylo::system_call::kSYS_getxattr:
      return io_manager->GetXattr(reinterpret_cast<const char *>(args[0]),
                                  reinterpret_cast<const char *>(args[1]),
                                  reinterpret_cast<void *>(args[2]), args[3]);
    case asylo::system_call::kSYS_lgetxattr:
      return io_manager->LGetXattr(reinterpret_cast<const char *>(args[0]),
                                   reinterpret_cast<const char *>(args[1]),
                                   reinterpret_cast<void *>(args[2]), args[3]);
    case asylo::system_call::kSYS_fgetxattr:
      return io_manager->FGetXattr(args[0],
                                   reinterpret_cast<const char *>(args[1]),
                                   reinterpret_cast<void *>(args[2]), args[3]);
    case asylo::system_call::kSYS_setxattr:
      return io_manager->SetXattr(reinterpret_cast<const char *>(args[0]),
                                  reinterpret_cast<const char *>(args[1]),
                                  reinterpret_cast<const void *>(args[2]),
                                  args[3], args[4]);
    case asylo::system_call::kSYS_lsetxattr:
      return io_manager->LSetXattr(reinterpret_cast<const char *>(args[0]),
                                   reinterpret_cast<const char *>(args[1]),
                                   reinterpret_cast<const void *>(args[2]),
                                   args[3], args[4]);
    case asylo::system_call::kSYS_fsetxattr:
      return io_manager->FSetXattr(
          args[0], reinterpret_cast<const char *>(args[1]),
          reinterpret_cast<const void *>(args[2]), args[3], args[4]);
    case asylo::system_call::kSYS_listxattr:
      return io_manager->ListXattr(reinterpret_cast<const char *>(args[0]),
                                   reinterpret_cast<char *>(args[1]), args[2]);
    case asylo::system_call::kSYS_llistxattr:
      return io_manager->LListXattr(reinterpret_cast<const char *>(args[0]),
                                    reinterpret_cast<char *>(args[1]), args[2]);
    case asylo::system_call::kSYS_flistxattr:
      return io_manager->FListXattr(args[0], reinterpret_cast<char *>(args[1]),
                                    args[2]);
    case asylo::system_call::kSYS_rt_sigaction:
      return asylo::RtSigaction(
          args[0], reinterpret_cast<const struct sigaction *>(args[1]),
          reinterpret_cast<struct sigaction *>(args[2]), args[3]);
    case asylo::system_call::kSYS_rt_sigprocmask:
      return asylo::RtSigprocmask(
          args[0], reinterpret_cast<const sigset_t *>(args[1]),
          reinterpret_cast<sigset_t *>(args[2]), args[3]);
    case asylo::system_call::kSYS_kill:
          return enc_untrusted_kill(args[0], static_cast<int>(args[1]));
    case asylo::system_call::kSYS_exit:
    case asylo::system_call::kSYS_exit_group:
      enc_exit(args[0]);
      errno = EAGAIN;
      return -1;  // Return -1 if exit fails somehow.
    default:
      errno = ENOSYS;
      return -1;
  }
}

}  // namespace system_call
}  // namespace asylo

extern "C" {

int64_t enclave_syscall(int sysno, uint64_t args[], size_t nargs) {
  return asylo::system_call::EnclaveSyscallWithDeps(
      sysno, args, nargs,
      asylo::system_call::EnclaveSyscallHelper::GetInstance(),
      &asylo::io::IOManager::GetInstance());
}

}  // extern "C"
