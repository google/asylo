#
#
# Copyright 2019 Asylo authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
"""Declares the include files and symbols to be processed by the code generator.

Describes the types that need to be generated with the default values on the
target implementation. For each type, only include the values/members that are
present in enclave C library as well as the target host library.
"""

from asylo.platform.system_call.type_conversions.types_parse_functions import define_constants
from asylo.platform.system_call.type_conversions.types_parse_functions import define_struct
from asylo.platform.system_call.type_conversions.types_parse_functions import set_klinux_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import write_output

set_klinux_prefix("kLinux")

define_constants(
    name="FileStatusFlag",
    values=[
        "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_EXCL",
        "O_TRUNC", "O_NONBLOCK", "O_DIRECT", "O_CLOEXEC"
    ],
    include_header_file="fcntl.h",
    multi_valued=True)

define_constants(
    name="FileModeFlag",
    values=[
        "S_IFMT", "S_IFDIR", "S_IFCHR", "S_IFBLK", "S_IFREG", "S_IFIFO",
        "S_IFLNK", "S_IFSOCK", "S_ISUID", "S_ISGID", "S_ISVTX", "S_IRUSR",
        "S_IWUSR", "S_IXUSR", "S_IRGRP", "S_IWGRP", "S_IXGRP", "S_IRWXG",
        "S_IROTH", "S_IWOTH", "S_IXOTH", "S_IRWXO"
    ],
    include_header_file="fcntl.h",
    multi_valued=True)

define_constants(
    name="FcntlCommand",
    values=[
        "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL", "F_GETPIPE_SZ",
        "F_SETPIPE_SZ"
    ],
    include_header_file="fcntl.h")

define_constants(
    name="AfFamily",
    values=[
        "AF_UNIX", "AF_LOCAL", "AF_INET", "AF_AX25", "AF_IPX", "AF_APPLETALK",
        "AF_X25", "AF_ATMPVC", "AF_INET6", "AF_DECnet", "AF_KEY", "AF_NETLINK",
        "AF_PACKET", "AF_RDS", "AF_PPPOX", "AF_LLC", "AF_CAN", "AF_TIPC",
        "AF_BLUETOOTH", "AF_ALG", "AF_VSOCK", "AF_UNSPEC"
    ],
    include_header_file="sys/socket.h")

define_constants(
    name="SocketType",
    values=[
        "SOCK_STREAM", "SOCK_DGRAM", "SOCK_SEQPACKET", "SOCK_RAW", "SOCK_RDM",
        "SOCK_PACKET", "SOCK_NONBLOCK", "SOCK_CLOEXEC"
    ],
    include_header_file="sys/socket.h",
    skip_conversions=True)

define_constants(
    name="FDFlag",
    values=["FD_CLOEXEC"],
    include_header_file="fcntl.h",
    multi_valued=True)

define_constants(
    name="TcpOptionName",
    values=["TCP_NODELAY", "TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"],
    include_header_file="netinet/tcp.h")

define_constants(
    name="IpV6OptionName",
    values=[
        "IPV6_V6ONLY", "IPV6_RECVPKTINFO", "IPV6_PKTINFO", "IPV6_RECVHOPLIMIT",
        "IPV6_HOPLIMIT", "IPV6_RECVHOPOPTS", "IPV6_HOPOPTS",
        "IPV6_RTHDRDSTOPTS", "IPV6_RECVRTHDR", "IPV6_RTHDR", "IPV6_RECVDSTOPTS",
        "IPV6_DSTOPTS"
    ],
    include_header_file="netinet/in.h")

define_constants(
    name="SocketOptionName",
    values=[
        "SO_DEBUG", "SO_REUSEADDR", "SO_TYPE", "SO_ERROR", "SO_DONTROUTE",
        "SO_BROADCAST", "SO_SNDBUF", "SO_RCVBUF", "SO_SNDBUFFORCE",
        "SO_RCVBUFFORCE", "SO_KEEPALIVE", "SO_OOBINLINE", "SO_NO_CHECK",
        "SO_PRIORITY", "SO_LINGER", "SO_BSDCOMPAT", "SO_REUSEPORT",
        "SO_RCVTIMEO", "SO_SNDTIMEO"
    ],
    include_header_file="sys/socket.h")

define_constants(
    name="FLockOperation",
    values=["LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN"],
    include_header_file="fcntl.h",
    multi_valued=True)

define_constants(
    name="InotifyFlag",
    values=["IN_NONBLOCK", "IN_CLOEXEC"],
    include_header_file="sys/inotify.h",
    multi_valued=True)

define_constants(
    name="InotifyEventMask",
    values=[
        "IN_ACCESS", "IN_ATTRIB", "IN_CLOSE_WRITE", "IN_CLOSE_NOWRITE",
        "IN_CREATE", "IN_DELETE", "IN_DELETE_SELF", "IN_MODIFY", "IN_MOVE_SELF",
        "IN_MOVED_FROM", "IN_MOVED_TO", "IN_OPEN", "IN_DONT_FOLLOW",
        "IN_EXCL_UNLINK", "IN_MASK_ADD", "IN_ONESHOT", "IN_ONLYDIR",
        "IN_IGNORED", "IN_ISDIR", "IN_Q_OVERFLOW", "IN_UNMOUNT"
    ],
    include_header_file="sys/inotify.h",
    multi_valued=True,
    data_type="uint32_t")

# List of errnos to be translated from the host native values to the enclave
# native values. This list was chosen as an intersection of errnos between the
# libc implementations empirically seen in and out of the enclave. Any errno
# values not listed here will not be translated to an enclave native value, but
# will instead be propagated into the enclave as the host native value OR'ed
# with 0x8000.
define_constants(
    name="ErrorNumber",
    values=[
        "E2BIG", "EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EADV",
        "EAFNOSUPPORT", "EAGAIN", "EALREADY", "EBADE", "EBADF", "EBADFD",
        "EBADMSG", "EBADR", "EBADRQC", "EBADSLT", "EBFONT", "EBUSY",
        "ECANCELED", "ECHILD", "ECHRNG", "ECOMM", "ECONNABORTED",
        "ECONNREFUSED", "ECONNRESET", "EDEADLOCK", "EDESTADDRREQ", "EDOM",
        "EDOTDOT", "EDQUOT", "EEXIST", "EFAULT", "EFBIG", "EHOSTDOWN",
        "EHOSTUNREACH", "EIDRM", "EILSEQ", "EINPROGRESS", "EINTR", "EINVAL",
        "EIO", "EISCONN", "EISDIR", "EL2HLT", "EL2NSYNC", "EL3HLT", "EL3RST",
        "ELIBACC", "ELIBBAD", "ELIBEXEC", "ELIBMAX", "ELIBSCN", "ELNRNG",
        "ELOOP", "EMFILE", "EMLINK", "EMSGSIZE", "EMULTIHOP", "ENAMETOOLONG",
        "ENETDOWN", "ENETRESET", "ENETUNREACH", "ENFILE", "ENOANO", "ENOBUFS",
        "ENOCSI", "ENODATA", "ENODEV", "ENOENT", "ENOEXEC", "ENOLCK", "ENOLINK",
        "ENOMEDIUM", "ENOMEM", "ENOMSG", "ENONET", "ENOPKG", "ENOPROTOOPT",
        "ENOSPC", "ENOSR", "ENOSTR", "ENOSYS", "ENOTBLK", "ENOTCONN", "ENOTDIR",
        "ENOTEMPTY", "ENOTRECOVERABLE", "ENOTSOCK", "ENOTTY", "ENOTUNIQ",
        "ENXIO", "EOPNOTSUPP", "EOVERFLOW", "EOWNERDEAD", "EPERM",
        "EPFNOSUPPORT", "EPIPE", "EPROTO", "EPROTONOSUPPORT", "EPROTOTYPE",
        "ERANGE", "EREMCHG", "EREMOTE", "EROFS", "ESHUTDOWN", "ESOCKTNOSUPPORT",
        "ESPIPE", "ESRCH", "ESRMNT", "ESTALE", "ESTRPIPE", "ETIME", "ETIMEDOUT",
        "ETOOMANYREFS", "ETXTBSY", "EUNATCH", "EUSERS", "EXDEV", "EXFULL"
    ],
    include_header_file="errno.h",
    multi_valued=False)

define_constants(
    name="SysconfConstant",
    values=[
        "_SC_ARG_MAX", "_SC_CHILD_MAX", "_SC_HOST_NAME_MAX",
        "_SC_LOGIN_NAME_MAX", "_SC_NGROUPS_MAX", "_SC_CLK_TCK", "_SC_OPEN_MAX",
        "_SC_PAGESIZE", "_SC_PAGE_SIZE", "_SC_RE_DUP_MAX", "_SC_STREAM_MAX",
        "_SC_SYMLOOP_MAX", "_SC_TTY_NAME_MAX", "_SC_TZNAME_MAX", "_SC_VERSION",
        "_SC_NPROCESSORS_CONF", "_SC_NPROCESSORS_ONLN", "_SC_PHYS_PAGES",
        "_SC_AVPHYS_PAGES", "_SC_BC_BASE_MAX", "_SC_BC_DIM_MAX",
        "_SC_BC_SCALE_MAX", "_SC_BC_STRING_MAX", "_SC_COLL_WEIGHTS_MAX",
        "_SC_EXPR_NEST_MAX", "_SC_LINE_MAX", "_SC_2_VERSION", "_SC_2_C_DEV",
        "_SC_2_FORT_DEV", "_SC_2_FORT_RUN", "_SC_2_LOCALEDEF", "_SC_2_SW_DEV"
    ],
    include_header_file="unistd.h")

define_constants(
    name="RecvSendFlag",
    values=[
        "MSG_OOB", "MSG_PEEK", "MSG_DONTROUTE", "MSG_CTRUNC", "MSG_PROXY",
        "MSG_TRUNC", "MSG_DONTWAIT", "MSG_EOR", "MSG_WAITALL", "MSG_FIN",
        "MSG_SYN", "MSG_CONFIRM", "MSG_RST", "MSG_ERRQUEUE", "MSG_NOSIGNAL",
        "MSG_MORE", "MSG_WAITFORONE", "MSG_FASTOPEN", "MSG_CMSG_CLOEXEC"
    ],
    include_header_file="sys/socket.h",
    multi_valued=True,
)

define_constants(
    name="BaseSignalNumber",
    values=[
        "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS",
        "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE",
        "SIGALRM", "SIGTERM", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP",
        "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM",
        "SIGPROF", "SIGWINCH", "SIGSYS", "SIGIO", "SIGPWR", "SIGRTMIN",
        "SIGRTMAX", "NSIG"
    ],
    include_header_file="signal.h",
    wrap_macros_with_if_defined=True)

define_constants(
    name="SigMaskAction",
    values=["SIG_BLOCK", "SIG_UNBLOCK", "SIG_SETMASK"],
    include_header_file="signal.h")

define_constants(
    name="ClockId",
    values=[
        "CLOCK_REALTIME",
        "CLOCK_MONOTONIC",
    ],
    include_header_file="time.h",
    data_type="clockid_t")

define_constants(
    name="ItimerType",
    values=["ITIMER_REAL", "ITIMER_VIRTUAL", "ITIMER_PROF"],
    include_header_file="sys/time.h")

define_constants(
    name="AddressInfoFlag",
    values=[
        "AI_CANONNAME", "AI_NUMERICHOST", "AI_V4MAPPED", "AI_ADDRCONFIG",
        "AI_ALL", "AI_PASSIVE", "AI_NUMERICSERV", "AI_IDN", "AI_CANONIDN"
    ],
    include_header_file="netdb.h",
    multi_valued=True)

define_constants(
    name="AddressInfoError",
    values=[
        "EAI_ADDRFAMILY", "EAI_AGAIN", "EAI_BADFLAGS", "EAI_FAIL", "EAI_FAMILY",
        "EAI_MEMORY", "EAI_NODATA", "EAI_NONAME", "EAI_SERVICE", "EAI_SOCKTYPE",
        "EAI_SYSTEM", "EAI_OVERFLOW", "EAI_INPROGRESS", "EAI_CANCELED",
        "EAI_ALLDONE", "EAI_INTR", "EAI_IDN_ENCODE"
    ],
    include_header_file="netdb.h")

define_constants(
    name="PollEvent",
    values=[
        "POLLIN", "POLLPRI", "POLLOUT", "POLLRDHUP", "POLLERR", "POLLHUP",
        "POLLNVAL", "POLLRDNORM", "POLLRDBAND", "POLLWRNORM", "POLLWRBAND"
    ],
    include_header_file="poll.h",
    multi_valued=True)

define_constants(
    name="EpollCtlOp",
    values=["EPOLL_CTL_ADD", "EPOLL_CTL_MOD", "EPOLL_CTL_DEL"],
    include_header_file="sys/epoll.h")

define_constants(
    name="EpollEvents",
    values=[
        "EPOLLIN", "EPOLLOUT", "EPOLLRDHUP", "EPOLLPRI", "EPOLLERR", "EPOLLHUP",
        "EPOLLET", "EPOLLONESHOT", "EPOLLWAKEUP", "EPOLLMSG"
    ],
    include_header_file="sys/epoll.h",
    multi_valued=True,
    data_type="uint32_t")

define_constants(
    name="IffFlag",
    values=[
        "IFF_UP", "IFF_BROADCAST", "IFF_DEBUG", "IFF_LOOPBACK",
        "IFF_POINTOPOINT", "IFF_NOTRAILERS", "IFF_RUNNING", "IFF_NOARP",
        "IFF_PROMISC", "IFF_ALLMULTI", "IFF_MULTICAST"
    ],
    include_header_file="net/if.h",
    multi_valued=True,
    data_type="unsigned int")

define_constants(
    name="RusageTarget",
    values=["RUSAGE_SELF", "RUSAGE_CHILDREN"],
    include_header_file="sys/resource.h")

define_constants(
    name="WaitOption",
    values=["WNOHANG", "WUNTRACED"],
    include_header_file="sys/wait.h")

define_constants(
    name="UtsNameLength",
    values=[
        "_UTSNAME_SYSNAME_LENGTH", "_UTSNAME_NODENAME_LENGTH",
        "_UTSNAME_RELEASE_LENGTH", "_UTSNAME_VERSION_LENGTH",
        "_UTSNAME_MACHINE_LENGTH", "_UTSNAME_DOMAIN_LENGTH"
    ],
    include_header_file="sys/utsname.h",
    skip_conversions=True)

define_constants(
    name="SyslogFacility",
    values=[
        "LOG_KERN", "LOG_USER", "LOG_LOCAL0", "LOG_LOCAL1", "LOG_LOCAL2",
        "LOG_LOCAL3", "LOG_LOCAL4", "LOG_LOCAL5", "LOG_LOCAL6", "LOG_LOCAL7"
    ],
    include_header_file="syslog.h")

define_constants(
    name="SyslogOption",
    values=[
        "LOG_PID", "LOG_CONS", "LOG_ODELAY", "LOG_NDELAY", "LOG_NOWAIT",
        "LOG_PERROR"
    ],
    include_header_file="syslog.h",
    multi_valued=True)

define_constants(
    name="SyslogLevel",
    values=[
        "LOG_EMERG", "LOG_ALERT", "LOG_CRIT", "LOG_ERR", "LOG_WARNING",
        "LOG_NOTICE", "LOG_INFO", "LOG_DEBUG"
    ],
    include_header_file="syslog.h")

define_constants(
    name="SignalFlag",
    values=["SA_NODEFER", "SA_RESETHAND"],
    include_header_file="signal.h",
    multi_valued=True,
    data_type="int64_t")

# The code that describes the cause of a signal.
define_constants(
    name="SignalCode",
    values=["SI_USER", "SI_QUEUE", "SI_TIMER", "SI_ASYNCIO", "SI_MESGQ"],
    include_header_file="signal.h")

define_struct(
    name="timespec",
    values=[
        ("int64_t", "tv_sec"),
        ("int64_t", "tv_nsec"),
    ],
    include_header_file="time.h",
    pack_attributes=False)

define_struct(
    name="timeval",
    values=[
        ("int64_t", "tv_sec"),
        ("int64_t", "tv_usec"),
    ],
    include_header_file="time.h",
    pack_attributes=False)

define_struct(
    name="tms",
    values=[
        ("int64_t", "tms_utime"),
        ("int64_t", "tms_stime"),
        ("int64_t", "tms_cutime"),
        ("int64_t", "tms_cstime"),
    ],
    include_header_file="sys/times.h",
    pack_attributes=False)

define_struct(
    name="utimbuf",
    values=[
        ("int64_t", "actime"),
        ("int64_t", "modtime"),
    ],
    include_header_file="utime.h",
    pack_attributes=False)

write_output()
