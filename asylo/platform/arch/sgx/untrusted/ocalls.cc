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

// Stubs invoked by edger8r generated bridge code for ocalls.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // For |domainname| field in struct utsname.
#endif
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <algorithm>

#include "absl/memory/memory.h"
#include "asylo/platform/arch/sgx/untrusted/generated_bridge_u.h"
#include "asylo/platform/arch/sgx/untrusted/sgx_client.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_proto_serializer.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/common/debug_strings.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/platform/core/shared_name.h"
#include "asylo/util/status.h"

#include "asylo/util/logging.h"

namespace {

// Stores a pointer to a function inside the enclave that translates
// |bridge_signum| to a value inside the enclave and calls the registered signal
// handler for that signal.
static void (*handle_signal_inside_enclave)(int, bridge_siginfo_t *,
                                            void *) = nullptr;

// Translates host |signum| to |bridge_signum|, and calls the function
// registered as the signal handler inside the enclave.
void TranslateToBridgeAndHandleSignal(int signum, siginfo_t *info,
                                      void *ucontext) {
  int bridge_signum = asylo::ToBridgeSignal(signum);
  if (bridge_signum < 0) {
    // Invalid incoming signal number.
    return;
  }
  struct bridge_siginfo_t bridge_siginfo;
  asylo::ToBridgeSigInfo(info, &bridge_siginfo);
  if (handle_signal_inside_enclave) {
    handle_signal_inside_enclave(bridge_signum, &bridge_siginfo, ucontext);
  }
}

// Triggers an ecall to enter an enclave to handle the incoming signal.
//
// In hardware mode, this is registered as the signal handler.
// In simulation mode, this is called if the signal arrives when the TCS is
// inactive.
void EnterEnclaveAndHandleSignal(int signum, siginfo_t *info, void *ucontext) {
  asylo::EnclaveSignalDispatcher::GetInstance()->EnterEnclaveAndHandleSignal(
      signum, info, ucontext);
}

// Checks the enclave TCS state to determine which function to call to handle
// the signal. If the TCS is active, calls the signal handler registered inside
// the enclave directly. If the TCS is inactive, triggers an ecall to enter
// enclave and handle the signal.
//
// In simulation mode, this is registered as the signal handler.
void HandleSignalInSim(int signum, siginfo_t *info, void *ucontext) {
  auto client_result =
      asylo::EnclaveSignalDispatcher::GetInstance()->GetClientForSignal(signum);
  if (!client_result.ok()) {
    return;
  }
  asylo::SgxClient *client =
      dynamic_cast<asylo::SgxClient *>(client_result.ValueOrDie());
  if (client->IsTcsActive()) {
    TranslateToBridgeAndHandleSignal(signum, info, ucontext);
  } else {
    EnterEnclaveAndHandleSignal(signum, info, ucontext);
  }
}

}  // namespace

// Threading implementation-defined untrusted thread donate routine.
extern "C" int __asylo_donate_thread(const char *name);

//////////////////////////////////////
//              IO                  //
//////////////////////////////////////

int ocall_enc_untrusted_puts(const char *str) {
  int rc = puts(str);
  // This routine is intended for debugging, so flush immediately to ensure
  // output is written in the event the enclave aborts with buffered output.
  fflush(stdout);
  return rc;
}

void *ocall_enc_untrusted_malloc(bridge_size_t size) {
  void *ret = malloc(static_cast<size_t>(size));
  return ret;
}

int ocall_enc_untrusted_open(const char *path_name, int flags, uint32_t mode) {
  int host_flags = asylo::FromBridgeFileFlags(flags);
  int ret = open(path_name, host_flags, mode);
  return ret;
}

int ocall_enc_untrusted_fcntl(int fd, int cmd, int64_t arg) {
  int ret;
  switch (cmd) {
    case F_SETFL:
      ret = fcntl(fd, cmd, asylo::FromBridgeFileFlags(arg));
      break;
    case F_SETFD:
      ret = fcntl(fd, cmd, asylo::FromBridgeFDFlags(arg));
      break;
    case F_GETFL:
      ret = fcntl(fd, cmd, arg);
      if (ret != -1) {
        ret = asylo::ToBridgeFileFlags(ret);
      }
      break;
    case F_GETFD:
      ret = fcntl(fd, cmd, arg);
      if (ret != -1) {
        ret = asylo::ToBridgeFDFlags(ret);
      }
      break;
    default:
      return -1;
  }
  return ret;
}

int ocall_enc_untrusted_stat(const char *pathname,
                             struct bridge_stat *stat_buffer) {
  struct stat host_stat_buffer;
  int ret = stat(pathname, &host_stat_buffer);
  asylo::ToBridgeStat(&host_stat_buffer, stat_buffer);
  return ret;
}

int ocall_enc_untrusted_fstat(int fd, struct bridge_stat *stat_buffer) {
  struct stat host_stat_buffer;
  int ret = fstat(fd, &host_stat_buffer);
  asylo::ToBridgeStat(&host_stat_buffer, stat_buffer);
  return ret;
}

int ocall_enc_untrusted_lstat(const char *pathname,
                              struct bridge_stat *stat_buffer) {
  struct stat host_stat_buffer;
  int ret = lstat(pathname, &host_stat_buffer);
  asylo::ToBridgeStat(&host_stat_buffer, stat_buffer);
  return ret;
}

bridge_ssize_t ocall_enc_untrusted_write_with_untrusted_ptr(int fd,
                                                            const void *buf,
                                                            int size) {
  return static_cast<bridge_ssize_t>(write(fd, buf, size));
}

bridge_ssize_t ocall_enc_untrusted_read_with_untrusted_ptr(int fd, void *buf,
                                                           int size) {
  return static_cast<bridge_ssize_t>(read(fd, buf, size));
}

//////////////////////////////////////
//             Sockets              //
//////////////////////////////////////

int ocall_enc_untrusted_connect(int sockfd,
                                const struct bridge_sockaddr *addr) {
  struct bridge_sockaddr tmp;
  socklen_t len = 0;
  asylo::FromBridgeSockaddr(addr, reinterpret_cast<struct sockaddr *>(&tmp),
                            &len);
  int ret = connect(sockfd, reinterpret_cast<struct sockaddr *>(&tmp), len);
  return ret;
}

int ocall_enc_untrusted_bind(int sockfd, const struct bridge_sockaddr *addr) {
  struct bridge_sockaddr tmp;
  socklen_t len = 0;
  asylo::FromBridgeSockaddr(
                     addr, reinterpret_cast<struct sockaddr *>(&tmp), &len);
  int ret = bind(sockfd,
                 reinterpret_cast<struct sockaddr *>(&tmp), len);
  return ret;
}

int ocall_enc_untrusted_accept(int sockfd, struct bridge_sockaddr *addr) {
  struct sockaddr_storage tmp;
  socklen_t tmp_len = sizeof(tmp);
  int ret = accept(sockfd, reinterpret_cast<struct sockaddr *>(&tmp), &tmp_len);
  if (ret == -1) {
    return ret;
  }
  asylo::ToBridgeSockaddr(reinterpret_cast<struct sockaddr *>(&tmp), tmp_len,
                          addr);
  return ret;
}

bridge_ssize_t ocall_enc_untrusted_sendmsg(int sockfd,
                                           const struct bridge_msghdr *msg,
                                           int flags) {
  struct msghdr tmp;
  if (!asylo::FromBridgeMsgHdr(msg, &tmp)) {
    errno = EFAULT;
    return -1;
  }
  auto buf = absl::make_unique<struct iovec[]>(msg->msg_iovlen);
  for (int i = 0; i < msg->msg_iovlen; ++i) {
    if (!asylo::FromBridgeIovec(&msg->msg_iov[i], &buf[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  tmp.msg_iov = buf.get();
  bridge_ssize_t ret =
      static_cast<bridge_ssize_t>(sendmsg(sockfd, &tmp, flags));
  return ret;
}

bridge_ssize_t ocall_enc_untrusted_recvmsg(int sockfd,
                                           struct bridge_msghdr *msg,
                                           int flags) {
  struct msghdr tmp;
  if (!asylo::FromBridgeMsgHdr(msg, &tmp)) {
    errno = EFAULT;
    return -1;
  }
  auto buf = absl::make_unique<struct iovec[]>(msg->msg_iovlen);
  for (int i = 0; i < msg->msg_iovlen; ++i) {
    if (!asylo::FromBridgeIovec(&msg->msg_iov[i], &buf[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  tmp.msg_iov = buf.get();
  bridge_ssize_t ret =
      static_cast<bridge_ssize_t>(recvmsg(sockfd, &tmp, flags));
  if (!asylo::ToBridgeIovecArray(&tmp, msg)) {
    errno = EFAULT;
    return -1;
  }
  return ret;
}

char *ocall_enc_untrusted_inet_ntop(int af, const void *src,
                                    bridge_size_t src_size, char *dst,
                                    bridge_size_t buf_size) {
  // src_size is needed so edgr8r copes the correct number of bytes out of the
  // enclave. This suppresses unused variable errors.
  (void)src_size;
  const char *ret = inet_ntop(af, src, dst, static_cast<size_t>(buf_size));
  // edgr8r does not support returning const char*
  return const_cast<char *>(ret);
}

int ocall_enc_untrusted_inet_pton(AfFamily af, const char *src, void *dst,
                                  bridge_size_t dst_size) {
  // The line below is needed to surpress unused variable errors, as |dst_size|
  // is needed for the edgr8r generated code.
  (void) dst_size;
  return inet_pton(asylo::FromBridgeAfFamily(af), src, dst);
}

int ocall_enc_untrusted_getaddrinfo(const char *node, const char *service,
                                    const char *serialized_hints,
                                    bridge_size_t serialized_hints_len,
                                    char **serialized_res_start,
                                    bridge_size_t *serialized_res_len) {
  struct addrinfo *hints;
  std::string tmp_serialized_hints(serialized_hints,
                              static_cast<size_t>(serialized_hints_len));
  if (!asylo::DeserializeAddrinfo(&tmp_serialized_hints, &hints)) {
    return -1;
  }
  if (hints) {
    hints->ai_flags = asylo::FromBridgeAddressInfoFlags(hints->ai_flags);
  }

  struct addrinfo *res;
  int ret = getaddrinfo(node, service, hints, &res);
  if (ret != 0) {
    return ret;
  }
  asylo::FreeDeserializedAddrinfo(hints);

  std::string tmp_serialized_res;
  if (!asylo::SerializeAddrinfo(res, &tmp_serialized_res)) {
    return -1;
  }
  freeaddrinfo(res);

  // Allocate memory for the enclave to copy the result; enclave will free this.
  size_t tmp_serialized_res_len = tmp_serialized_res.length();
  char *serialized_res = static_cast<char *>(malloc(tmp_serialized_res_len));
  memcpy(serialized_res, tmp_serialized_res.c_str(), tmp_serialized_res_len);
  *serialized_res_start = serialized_res;
  *serialized_res_len = static_cast<bridge_size_t>(tmp_serialized_res_len);
  return ret;
}

int ocall_enc_untrusted_getsockopt(int sockfd, int level, int optname,
                                   void *optval, unsigned int optlen_in,
                                   unsigned int *optlen_out) {
  int ret =
      getsockopt(sockfd, level, asylo::FromBridgeOptionName(level, optname),
                 optval, reinterpret_cast<socklen_t *>(&optlen_in));
  *optlen_out = optlen_in;
  return ret;
}

int ocall_enc_untrusted_setsockopt(int sockfd, int level, int optname,
                                   const void *optval, bridge_size_t optlen) {
  return setsockopt(sockfd, level, asylo::FromBridgeOptionName(level, optname),
                    optval, static_cast<socklen_t>(optlen));
}

int ocall_enc_untrusted_getsockname(int sockfd, struct bridge_sockaddr *addr) {
  struct sockaddr_storage tmp;
  socklen_t tmp_len = sizeof(tmp);
  int ret =
      getsockname(sockfd, reinterpret_cast<struct sockaddr *>(&tmp), &tmp_len);
  asylo::ToBridgeSockaddr(reinterpret_cast<struct sockaddr *>(&tmp), tmp_len,
                          addr);
  return ret;
}

int ocall_enc_untrusted_getpeername(int sockfd, struct bridge_sockaddr *addr) {
  struct sockaddr_storage tmp;
  socklen_t tmp_len = sizeof(tmp);
  int ret =
      getpeername(sockfd, reinterpret_cast<struct sockaddr *>(&tmp), &tmp_len);
  asylo::ToBridgeSockaddr(reinterpret_cast<struct sockaddr *>(&tmp), tmp_len,
                          addr);
  return ret;
}

ssize_t ocall_enc_untrusted_recvfrom(const char *serialized_args,
                                     bridge_ssize_t serialized_args_len,
                                     char **buf_ptr, char **serialized_output,
                                     bridge_ssize_t *serialized_output_len) {
  std::string serialized_args_str(serialized_args, serialized_args_len);
  int sockfd = 0;
  size_t len = 0;
  int flags = 0;
  if (!asylo::DeserializeRecvFromArgs(serialized_args, &sockfd, &len, &flags) ||
      !buf_ptr) {
    errno = EINVAL;
    return -1;
  }
  *buf_ptr = static_cast<char *>(malloc(len));
  if (serialized_output) {
    struct sockaddr_storage src_addr;
    struct sockaddr *src_addr_ptr =
        reinterpret_cast<struct sockaddr *>(&src_addr);
    socklen_t addrlen;
    int ret = recvfrom(sockfd, *buf_ptr, len, flags, src_addr_ptr, &addrlen);
    size_t src_addr_len = 0;
    // The caller is responsible for freeing the memory allocated by
    // SerializeRecvFromSrcAddr.
    if (!asylo::SerializeRecvFromSrcAddr(src_addr_ptr, serialized_output,
                                         &src_addr_len)) {
      errno = EINVAL;
      return -1;
    }
    *serialized_output_len = static_cast<bridge_size_t>(src_addr_len);
    return ret;
  } else {
    return recvfrom(sockfd, *buf_ptr, len, flags, nullptr, nullptr);
  }
}

//////////////////////////////////////
//           poll.h                 //
//////////////////////////////////////

int ocall_enc_untrusted_poll(struct bridge_pollfd *fds, unsigned int nfds,
                             int timeout) {
  auto tmp = absl::make_unique<pollfd[]>(nfds);
  for (int i = 0; i < nfds; ++i) {
    if (!asylo::FromBridgePollfd(&fds[i], &tmp[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  int ret = poll(tmp.get(), nfds, timeout);
  for (int i = 0; i < nfds; ++i) {
    if (!asylo::ToBridgePollfd(&tmp[i], &fds[i])) {
      errno = EFAULT;
      return -1;
    }
  }
  return ret;
}

//////////////////////////////////////
//           epoll.h                //
//////////////////////////////////////

int ocall_enc_untrusted_epoll_create(int size) { return epoll_create(size); }

int ocall_enc_untrusted_epoll_ctl(const char *serialized_args,
                                  bridge_size_t serialized_args_len) {
  std::string serialized_args_str(serialized_args,
                             static_cast<size_t>(serialized_args_len));
  int epfd = 0;
  int op = 0;
  int hostfd = 0;
  struct epoll_event event;
  if (!asylo::DeserializeEpollCtlArgs(serialized_args_str, &epfd, &op, &hostfd,
                                      &event)) {
    errno = EINVAL;
    return -1;
  }
  return epoll_ctl(epfd, op, hostfd, &event);
}

int ocall_enc_untrusted_epoll_wait(const char *serialized_args,
                                   bridge_size_t serialized_args_len,
                                   char **serialized_events,
                                   bridge_size_t *serialized_events_len) {
  int epfd = 0;
  int maxevents = 0;
  int timeout = 0;
  std::string serialized_args_str(serialized_args,
                             static_cast<size_t>(serialized_args_len));
  if (!asylo::DeserializeEpollWaitArgs(serialized_args_str, &epfd, &maxevents,
                                       &timeout)) {
    errno = EINVAL;
    return -1;
  }
  struct epoll_event *event_array = static_cast<struct epoll_event *>(
      malloc(sizeof(struct epoll_event) * maxevents));
  asylo::MallocUniquePtr<struct epoll_event> event_array_ptr(event_array);
  int ret = epoll_wait(epfd, event_array, maxevents, timeout);
  size_t len = 0;
  if (!asylo::SerializeEvents(event_array, ret, serialized_events, &len)) {
    errno = EINVAL;
    return -1;
  }
  *serialized_events_len = static_cast<bridge_size_t>(len);
  return ret;
}

//////////////////////////////////////
//           inotify.h              //
//////////////////////////////////////

int ocall_enc_untrusted_inotify_init1(int non_block) {
  int flags = non_block ? IN_NONBLOCK : 0;
  return inotify_init1(flags);
}

int ocall_enc_untrusted_inotify_add_watch(const char *serialized_args,
                                          bridge_size_t serialized_args_len) {
  std::string serialized_args_str(serialized_args, serialized_args_len);
  int fd = 0;
  char *pathname = nullptr;
  asylo::MallocUniquePtr<char> pathname_ptr(pathname);
  uint32_t mask = 0;
  if (!asylo::DeserializeInotifyAddWatchArgs(serialized_args_str, &fd,
                                             &pathname, &mask)) {
    errno = EINVAL;
    return -1;
  }
  return inotify_add_watch(fd, pathname, mask);
}

int ocall_enc_untrusted_inotify_rm_watch(const char *serialized_args,
                                         bridge_size_t serialized_args_len) {
  std::string serialized_args_str(serialized_args, serialized_args_len);
  int fd = 0;
  int wd = 0;
  if (!asylo::DeserializeInotifyRmWatchArgs(serialized_args_str, &fd, &wd)) {
    errno = EINVAL;
    return -1;
  }
  return inotify_rm_watch(fd, wd);
}

int ocall_enc_untrusted_inotify_read(int fd, bridge_size_t count,
                                     char **serialized_events,
                                     bridge_size_t *serialized_events_len) {
  size_t buf_size =
      std::max(sizeof(struct inotify_event) + NAME_MAX + 1, count);
  char *buf = static_cast<char *>(malloc(buf_size));
  asylo::MallocUniquePtr<char> buf_ptr(buf);
  int bytes_read = read(fd, buf, buf_size);
  if (bytes_read < 0) {
    // Errno will be set by read.
    return -1;
  }
  size_t len = 0;
  if (!asylo::SerializeInotifyEvents(buf, bytes_read, serialized_events,
                                     &len)) {
    return -1;
  }
  *serialized_events_len = static_cast<bridge_size_t>(len);
  return 0;
}

//////////////////////////////////////
//           ifaddrs.h              //
//////////////////////////////////////

int ocall_enc_untrusted_getifaddrs(char **serialized_ifaddrs,
                                   bridge_ssize_t *serialized_ifaddrs_len) {
  struct ifaddrs *ifaddr_list = nullptr;
  int ret = getifaddrs(&ifaddr_list);
  if (ret != 0) {
    return -1;
  }
  size_t len = 0;
  if (!asylo::SerializeIfAddrs(ifaddr_list, serialized_ifaddrs, &len)) {
    freeifaddrs(ifaddr_list);
    return -1;
  }
  *serialized_ifaddrs_len = static_cast<bridge_ssize_t>(len);
  freeifaddrs(ifaddr_list);
  return ret;
}

//////////////////////////////////////
//           sched.h                //
//////////////////////////////////////

int ocall_enc_untrusted_sched_getaffinity(int64_t pid, BridgeCpuSet *mask) {
  cpu_set_t host_mask;
  if (BRIDGE_CPU_SET_MAX_CPUS != CPU_SETSIZE) {
    LOG(ERROR) << "sched_getaffinity: CPU_SETSIZE (" << CPU_SETSIZE
               << ") is not equal to " << BRIDGE_CPU_SET_MAX_CPUS;
    errno = ENOSYS;
    return -1;
  }

  int ret =
      sched_getaffinity(static_cast<pid_t>(pid), sizeof(cpu_set_t), &host_mask);

  // Translate from host cpu_set_t to bridge_cpu_set_t.
  int total_cpus = CPU_COUNT(&host_mask);
  asylo::BridgeCpuSetZero(mask);
  for (int cpu = 0, cpus_so_far = 0; cpus_so_far < total_cpus; ++cpu) {
    if (CPU_ISSET(cpu, &host_mask)) {
      asylo::BridgeCpuSetAddBit(cpu, mask);
      ++cpus_so_far;
    }
  }

  return ret;
}

//////////////////////////////////////
//          signal.h                //
//////////////////////////////////////

int ocall_enc_untrusted_register_signal_handler(
    int bridge_signum, const struct BridgeSignalHandler *handler,
    const char *name) {
  std::string enclave_name(name);
  int signum = asylo::FromBridgeSignal(bridge_signum);
  if (signum < 0) {
    errno = EINVAL;
    return -1;
  }
  auto manager_result = asylo::EnclaveManager::Instance();
  if (!manager_result.ok()) {
    return -1;
  }
  // Registers the signal with an enclave so when the signal arrives,
  // EnclaveManager knows which enclave to enter to handle the signal.
  asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  asylo::EnclaveClient *client = manager->GetClient(enclave_name);
  const asylo::EnclaveClient *old_client =
      asylo::EnclaveSignalDispatcher::GetInstance()->RegisterSignal(signum,
                                                                    client);
  if (old_client) {
    LOG(WARNING) << "Overwriting the signal handler for signal: " << signum
                 << " registered by enclave: " << manager->GetName(old_client);
  }
  struct sigaction newact;
  if (!handler || !handler->sigaction) {
    // Hardware mode: The registered signal handler triggers an ecall to enter
    // the enclave and handle the signal.
    newact.sa_sigaction = &EnterEnclaveAndHandleSignal;
  } else {
    // Simulation mode: The registered signal handler does the same as hardware
    // mode if the TCS is active, or calls the signal handler registered inside
    // the enclave directly if the TCS is inactive.
    handle_signal_inside_enclave = handler->sigaction;
    newact.sa_sigaction = &HandleSignalInSim;
  }
  if (handler) {
    asylo::FromBridgeSigSet(&handler->mask, &newact.sa_mask);
  }
  // Set the flag so that sa_sigaction is registered as the signal handler
  // instead of sa_handler.
  newact.sa_flags |= SA_SIGINFO;
  struct sigaction oldact;
  return sigaction(signum, &newact, &oldact);
}

int ocall_enc_untrusted_sigprocmask(int how, const bridge_sigset_t *set,
                                    bridge_sigset_t *oldset) {
  sigset_t tmp_set;
  asylo::FromBridgeSigSet(set, &tmp_set);
  sigset_t tmp_oldset;
  int ret =
      sigprocmask(asylo::FromBridgeSigMaskAction(how), &tmp_set, &tmp_oldset);
  asylo::ToBridgeSigSet(&tmp_oldset, oldset);
  return ret;
}

int ocall_enc_untrusted_raise(int bridge_sig) {
  int sig = asylo::FromBridgeSignal(bridge_sig);
  if (sig < 0) {
    errno = EINVAL;
    return -1;
  }
  return raise(sig);
}

//////////////////////////////////////
//         sys/resource.h           //
//////////////////////////////////////

int ocall_enc_untrusted_getrusage(enum RUsageTarget who,
                                  struct BridgeRUsage *bridge_usage) {
  struct rusage usage;
  int ret = getrusage(asylo::FromBridgeRUsageTarget(who), &usage);
  asylo::ToBridgeRUsage(&usage, bridge_usage);
  return ret;
}

//////////////////////////////////////
//           sys/file.h             //
//////////////////////////////////////

int ocall_enc_untrusted_flock(int fd, int operation) {
  return flock(fd, asylo::FromBridgeFLockOperation(operation));
}

//////////////////////////////////////
//          sys/select.h            //
//////////////////////////////////////

int ocall_enc_untrusted_select(int nfds, BridgeFDSet *bridge_readfds,
                               BridgeFDSet *bridge_writefds,
                               BridgeFDSet *bridge_exceptfds,
                               bridge_timeval *bridge_timeout) {
  fd_set readfds, writefds, exceptfds;
  if (bridge_readfds && !asylo::FromBridgeFDSet(bridge_readfds, &readfds)) {
    errno = EBADE;
    return -1;
  }
  if (bridge_writefds && !asylo::FromBridgeFDSet(bridge_writefds, &writefds)) {
    errno = EBADE;
    return -1;
  }
  if (bridge_exceptfds &&
      !asylo::FromBridgeFDSet(bridge_exceptfds, &exceptfds)) {
    errno = EBADE;
    return -1;
  }

  struct timeval timeout;
  if (!asylo::FromBridgeTimeVal(bridge_timeout, &timeout)) {
    errno = EBADE;
    return -1;
  }
  int ret = select(nfds, &readfds, &writefds, &exceptfds, &timeout);

  if (bridge_readfds && !asylo::ToBridgeFDSet(&readfds, bridge_readfds)) {
    errno = EBADE;
    return -1;
  }
  if (bridge_writefds && !asylo::ToBridgeFDSet(&writefds, bridge_writefds)) {
    errno = EBADE;
    return -1;
  }
  if (bridge_exceptfds && !asylo::ToBridgeFDSet(&exceptfds, bridge_exceptfds)) {
    errno = EBADE;
    return -1;
  }

  return ret;
}

//////////////////////////////////////
//          sys/syslog.h            //
//////////////////////////////////////

void ocall_enc_untrusted_openlog(const char *ident, int option, int facility) {
  openlog(ident, asylo::FromBridgeSysLogOption(option),
          asylo::FromBridgeSysLogFacility(facility));
}

void ocall_enc_untrusted_syslog(int priority, const char *message) {
  syslog(asylo::FromBridgeSysLogPriority(priority), "%s", message);
}

//////////////////////////////////////
//           time.h                 //
//////////////////////////////////////

int ocall_enc_untrusted_nanosleep(const struct bridge_timespec *req,
                                  struct bridge_timespec *rem) {
  int ret = nanosleep(reinterpret_cast<const struct timespec *>(req),
                      reinterpret_cast<struct timespec *>(rem));
  return ret;
}

int ocall_enc_untrusted_times(struct BridgeTms *bridge_buf) {
  struct tms buf;
  int ret = times(&buf);
  if (!asylo::ToBridgeTms(&buf, bridge_buf)) {
    errno = EFAULT;
    return -1;
  }
  return ret;
}

int ocall_enc_untrusted_clock_gettime(bridge_clockid_t clk_id,
                                      struct bridge_timespec *tp) {
  int ret = clock_gettime(static_cast<clockid_t>(clk_id),
                          reinterpret_cast<struct timespec *>(tp));
  return ret;
}

int ocall_enc_untrusted_setitimer(enum TimerType which,
                                  struct BridgeITimerVal *bridge_new_value,
                                  struct BridgeITimerVal *bridge_old_value) {
  itimerval new_value, old_value;
  if (!asylo::FromBridgeITimerVal(bridge_new_value, &new_value)) {
    errno = EFAULT;
    return -1;
  }
  int ret =
      setitimer(asylo::FromBridgeTimerType(which), &new_value, &old_value);
  if (bridge_old_value &&
      !asylo::ToBridgeITimerVal(&old_value, bridge_old_value)) {
    errno = EFAULT;
    return -1;
  }
  return ret;
}

//////////////////////////////////////
//           sys/time.h             //
//////////////////////////////////////

int ocall_enc_untrusted_gettimeofday(struct bridge_timeval *tv, void *tz) {
  return gettimeofday(reinterpret_cast<struct timeval *>(tv), nullptr);
}

//////////////////////////////////////
//         sys/utsname.h            //
//////////////////////////////////////

int ocall_enc_untrusted_uname(struct BridgeUtsName *bridge_utsname_val) {
  if (!bridge_utsname_val) {
    errno = EFAULT;
    return -1;
  }

  struct utsname utsname_val;
  int ret = uname(&utsname_val);
  if (ret != 0) {
    return ret;
  }

  if (!asylo::ConvertUtsName(utsname_val, bridge_utsname_val)) {
    errno = EINTR;
    return -1;
  }

  return ret;
}

//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

int ocall_enc_untrusted_pipe(int pipefd[2]) {
  int ret = pipe(pipefd);
  return ret;
}

int64_t ocall_enc_untrusted_sysconf(enum SysconfConstants bridge_name) {
  int name = asylo::FromBridgeSysconfConstants(bridge_name);
  int64_t ret = -1;
  if (name != -1) {
    ret = sysconf(name);
  }
  return ret;
}

uint32_t ocall_enc_untrusted_sleep(uint32_t seconds) { return sleep(seconds); }

//////////////////////////////////////
//             wait.h               //
//////////////////////////////////////

pid_t ocall_enc_untrusted_wait3(struct BridgeWStatus *wstatus, int options,
                                struct BridgeRUsage *rusage) {
  struct rusage tmp_rusage;
  int tmp_wstatus;
  pid_t ret =
      wait3(&tmp_wstatus, asylo::FromBridgeWaitOptions(options), &tmp_rusage);
  asylo::ToBridgeRUsage(&tmp_rusage, rusage);
  if (wstatus) {
    *wstatus = asylo::ToBridgeWStatus(tmp_wstatus);
  }
  return ret;
}

//////////////////////////////////////
//           utime.h                //
//////////////////////////////////////

int ocall_enc_untrusted_utime(const char *filename,
                              const struct bridge_utimbuf *times) {
  struct utimbuf tmp;
  return utime(filename, asylo::FromBridgeUtimbuf(times, &tmp));
}

//////////////////////////////////////
//           Runtime support        //
//////////////////////////////////////

void *ocall_enc_untrusted_acquire_shared_resource(SharedNameKind kind,
                                                  const char *name) {
  asylo::SharedName shared_name(kind, std::string(name));
  auto manager_result = asylo::EnclaveManager::Instance();
  if (manager_result.ok()) {
    return manager_result.ValueOrDie()
        ->shared_resources()
        ->AcquireResource<void>(shared_name);
  } else {
    return nullptr;
  }
}

int ocall_enc_untrusted_release_shared_resource(SharedNameKind kind,
                                                const char *name) {
  asylo::SharedName shared_name(kind, std::string(name));
  auto manager_result = asylo::EnclaveManager::Instance();
  if (manager_result.ok()) {
    return manager_result.ValueOrDie()->shared_resources()->ReleaseResource(
        shared_name);
  }
  return false;
}

//////////////////////////////////////
//           Debugging              //
//////////////////////////////////////

void ocall_enc_untrusted_hex_dump(const void *buf, int nbytes) {
  fprintf(stderr, "%s\n", asylo::buffer_to_hex_string(buf, nbytes).c_str());
}

//////////////////////////////////////
//           Threading              //
//////////////////////////////////////

int ocall_enc_untrusted_thread_create(const char *name) {
  __asylo_donate_thread(name);
  return 0;
}
