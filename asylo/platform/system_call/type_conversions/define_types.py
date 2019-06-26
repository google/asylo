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
present in newlib as well as the target host library.
"""

from asylo.platform.system_call.type_conversions.types_parse_functions import define_enum
from asylo.platform.system_call.type_conversions.types_parse_functions import define_struct
from asylo.platform.system_call.type_conversions.types_parse_functions import include
from asylo.platform.system_call.type_conversions.types_parse_functions import set_bridge_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import set_klinux_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import write_output

include("fcntl.h")
include("netdb.h")
include("netinet/tcp.h")
include("stdint.h")
include("sys/inotify.h")
include("sys/socket.h")

set_klinux_prefix("kLinux")
set_bridge_prefix("bridge")

define_enum(
    name="FileStatusFlag",
    values=[
        "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_EXCL",
        "O_TRUNC", "O_NONBLOCK", "O_DIRECT", "O_CLOEXEC"
    ],
    multi_valued=True)

define_enum(
    name="FcntlCommand",
    values=[
        "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL", "F_GETPIPE_SZ",
        "F_SETPIPE_SZ"
    ],
    default_value_host=-1,
    default_value_newlib=-1)

define_enum(
    name="AfFamily",
    values=[
        "AF_UNIX", "AF_LOCAL", "AF_INET", "AF_AX25", "AF_IPX", "AF_APPLETALK",
        "AF_X25", "AF_ATMPVC", "AF_INET6", "AF_DECnet", "AF_KEY", "AF_NETLINK",
        "AF_PACKET", "AF_RDS", "AF_PPPOX", "AF_LLC", "AF_CAN", "AF_TIPC",
        "AF_BLUETOOTH", "AF_ALG", "AF_VSOCK", "AF_UNSPEC"
    ],
    default_value_host="AF_UNSPEC",
    default_value_newlib="AF_UNSPEC")

define_enum(
    name="SocketType",
    values=[
        "SOCK_STREAM", "SOCK_DGRAM", "SOCK_SEQPACKET", "SOCK_RAW", "SOCK_RDM",
        "SOCK_PACKET", "SOCK_NONBLOCK", "SOCK_CLOEXEC"
    ],
    skip_conversions=True)

define_enum(name="FDFlag", values=["FD_CLOEXEC"], multi_valued=True)

define_enum(
    name="TcpOptionName",
    values=["TCP_NODELAY", "TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"],
    default_value_host=-1,
    default_value_newlib=-1)

define_enum(
    name="IpV6OptionName",
    values=[
        "IPV6_V6ONLY", "IPV6_RECVPKTINFO", "IPV6_PKTINFO", "IPV6_RECVHOPLIMIT",
        "IPV6_HOPLIMIT", "IPV6_RECVHOPOPTS", "IPV6_HOPOPTS",
        "IPV6_RTHDRDSTOPTS", "IPV6_RECVRTHDR", "IPV6_RTHDR", "IPV6_RECVDSTOPTS",
        "IPV6_DSTOPTS"
    ],
    default_value_host=-1,
    default_value_newlib=-1)

define_enum(
    name="SocketOptionName",
    values=[
        "SO_DEBUG", "SO_REUSEADDR", "SO_TYPE", "SO_ERROR", "SO_DONTROUTE",
        "SO_BROADCAST", "SO_SNDBUF", "SO_RCVBUF", "SO_SNDBUFFORCE",
        "SO_RCVBUFFORCE", "SO_KEEPALIVE", "SO_OOBINLINE", "SO_NO_CHECK",
        "SO_PRIORITY", "SO_LINGER", "SO_BSDCOMPAT", "SO_REUSEPORT",
        "SO_RCVTIMEO", "SO_SNDTIMEO"
    ],
    default_value_host=-1,
    default_value_newlib=-1)

define_enum(
    name="FLockOperation",
    values=["LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN"],
    multi_valued=True)

define_enum(
    name="InotifyFlag", values=["IN_NONBLOCK", "IN_CLOEXEC"], multi_valued=True)

define_enum(
    name="InotifyEventMask",
    values=[
        "IN_ACCESS", "IN_MODIFY", "IN_ATTRIB", "IN_CLOSE_WRITE",
        "IN_CLOSE_NOWRITE", "IN_OPEN", "IN_MOVED_FROM", "IN_MOVED_TO",
        "IN_CREATE", "IN_DELETE", "IN_DELETE_SELF", "IN_MOVE_SELF",
        "IN_UNMOUNT", "IN_Q_OVERFLOW", "IN_IGNORED"
    ],
    multi_valued=True)

define_struct(
    name="stat",
    values=[("int64_t", "st_dev"), ("int64_t", "st_ino"),
            ("int64_t", "st_mode"), ("int64_t", "st_nlink"),
            ("int64_t", "st_uid"), ("int64_t", "st_gid"),
            ("int64_t", "st_rdev"), ("int64_t", "st_size"),
            ("int64_t", "st_atime"), ("int64_t", "st_mtime"),
            ("int64_t", "st_ctime"), ("int64_t", "st_blksize"),
            ("int64_t", "st_blocks")])

write_output()
