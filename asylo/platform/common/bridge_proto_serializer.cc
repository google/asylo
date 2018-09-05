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

#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string>

#include "asylo/platform/common/bridge_proto_serializer.h"

namespace asylo {
namespace {

// Sockaddr conversion functions
bool ConvertToSockaddr(const SockaddrProto &in, struct sockaddr **out) {
  if (!out) return false;

  if (in.family_case() == SockaddrProto::kSockaddrIn6) {  // IPv6
    struct sockaddr_in6 *sock = static_cast<struct sockaddr_in6 *>(
        calloc(1, sizeof(struct sockaddr_in6)));
    sock->sin6_family = AF_INET6;
    sock->sin6_port = in.sockaddr_in6().sin6_port();
    sock->sin6_flowinfo = in.sockaddr_in6().sin6_flowinfo();
    memcpy(&(sock->sin6_addr.s6_addr), in.sockaddr_in6().sin6_addr().c_str(),
           kIn6AddrNumBytes);
    sock->sin6_scope_id = in.sockaddr_in6().sin6_scope_id();
    *out = reinterpret_cast<struct sockaddr *>(sock);
  } else if (in.family_case() == SockaddrProto::kSockaddrIn) {  // IPv4
    struct sockaddr_in *sock = static_cast<struct sockaddr_in *>(
        calloc(1, sizeof(struct sockaddr_in)));
    sock->sin_family = AF_INET;
    sock->sin_port = in.sockaddr_in().sin_port();
    sock->sin_addr.s_addr = in.sockaddr_in().sin_addr();
    *out = reinterpret_cast<struct sockaddr *>(sock);
  } else {
    return false;  // unsupported sa_family
  }
  return true;
}

bool ConvertToSockaddrProtobuf(const struct sockaddr *in, SockaddrProto *out) {
  if (!in || !out) return false;

  if (in->sa_family == AF_INET6) {  // IPv6
    SockaddrProto::SockaddrIn6 *sock_in6_proto = out->mutable_sockaddr_in6();
    const struct sockaddr_in6 *sock =
        reinterpret_cast<const struct sockaddr_in6 *>(in);
    sock_in6_proto->set_sin6_port(sock->sin6_port);
    sock_in6_proto->set_sin6_flowinfo(sock->sin6_flowinfo);
    sock_in6_proto->set_sin6_addr(
        std::string(reinterpret_cast<const char *>(&(sock->sin6_addr.s6_addr)),
               kIn6AddrNumBytes));
    sock_in6_proto->set_sin6_scope_id(sock->sin6_scope_id);
  } else if (in->sa_family == AF_INET) {  // IPv4
    SockaddrProto::SockaddrIn *sock_in_proto = out->mutable_sockaddr_in();
    const struct sockaddr_in *sock =
        reinterpret_cast<const struct sockaddr_in *>(in);
    sock_in_proto->set_sin_port(sock->sin_port);
    sock_in_proto->set_sin_addr(sock->sin_addr.s_addr);
  } else {
    return false;  // unsupported sa_family
  }
  return true;
}

// Addrinfo Conversion Functions
bool SetAddrinfoCanonname(const std::string *canonname, struct addrinfo *info) {
  info->ai_canonname = strdup(canonname->c_str());
  if (info->ai_canonname == nullptr) {
    return false;
  }
  return true;
}

bool ConvertToAddrinfo(const AddrinfosProto *in, struct addrinfo **out) {
  if (!in || !out) return false;

  struct addrinfo *prev_info = nullptr;
  for (int i = 0; i < in->addrinfos().size(); i++) {
    const AddrinfoProto info_proto = in->addrinfos(i);
    struct addrinfo *info =
        static_cast<struct addrinfo *>(malloc(sizeof(struct addrinfo)));
    if (info == nullptr) return false;

    memset(info, 0, sizeof(struct addrinfo));
    info->ai_flags = info_proto.ai_flags();
    info->ai_family = info_proto.ai_family();
    info->ai_socktype = info_proto.ai_socktype();
    info->ai_protocol = info_proto.ai_protocol();
    info->ai_addrlen = info_proto.ai_addrlen();
    if (info_proto.has_ai_addr() &&
        !ConvertToSockaddr(info_proto.ai_addr(), &info->ai_addr)) {
      return false;
    }
    if (info_proto.has_ai_canonname() &&
        !SetAddrinfoCanonname(&info_proto.ai_canonname(), info)) {
      return false;
    }

    // Construct addrinfo linked list
    if (!prev_info) {
      *out = info;
    } else {
      prev_info->ai_next = info;
    }
    prev_info = info;
  }

  return true;
}

// Arbitrary max length of ai_canonname. This maximum is above anything we would
// expect for a non-malicous input. POSIX does not specify any maximum length.
constexpr int kMaxCannonnameLen = 4096;
bool ConvertToAddrinfoProtobuf(const struct addrinfo *in, AddrinfosProto *out) {
  if (!in || !out) return false;

  for (const struct addrinfo *info = in; info != nullptr;
       info = info->ai_next) {
    AddrinfoProto *info_proto = out->add_addrinfos();
    info_proto->set_ai_flags(info->ai_flags);
    info_proto->set_ai_family(info->ai_family);
    info_proto->set_ai_socktype(info->ai_socktype);
    info_proto->set_ai_protocol(info->ai_protocol);
    info_proto->set_ai_addrlen(info->ai_addrlen);
    if (info->ai_addr) {
      SockaddrProto *sock_proto = info_proto->mutable_ai_addr();
      if (!ConvertToSockaddrProtobuf(info->ai_addr, sock_proto)) {
        return false;
      }
    }
    if (info->ai_canonname) {
      int canonname_len = strnlen(info->ai_canonname, kMaxCannonnameLen);
      info_proto->set_ai_canonname(std::string(info->ai_canonname, canonname_len));
    }
  }

  return true;
}

// Epoll conversion functions.
void ConvertToEpollEventProtobuf(const struct epoll_event *event,
                                 EpollEvent *event_proto) {
  int flags = event->events;
  if (flags & EPOLLIN) event_proto->add_event_flags(EpollEvent::PROTO_IN);
  if (flags & EPOLLPRI) event_proto->add_event_flags(EpollEvent::PROTO_PRI);
  if (flags & EPOLLOUT) event_proto->add_event_flags(EpollEvent::PROTO_OUT);
  if (flags & EPOLLMSG) event_proto->add_event_flags(EpollEvent::PROTO_MSG);
  if (flags & EPOLLERR) event_proto->add_event_flags(EpollEvent::PROTO_ERR);
  if (flags & EPOLLHUP) event_proto->add_event_flags(EpollEvent::PROTO_HUP);
  if (flags & EPOLLRDHUP) event_proto->add_event_flags(EpollEvent::PROTO_RDHUP);
  if (flags & EPOLLWAKEUP)
    event_proto->add_event_flags(EpollEvent::PROTO_WAKEUP);
  if (flags & EPOLLONESHOT)
    event_proto->add_event_flags(EpollEvent::PROTO_ONESHOT);
  if (flags & EPOLLET) event_proto->add_event_flags(EpollEvent::PROTO_ET);
  event_proto->set_data(event->data.u64);
}

void ConvertToEpollEvent(const EpollEvent &event_proto,
                         struct epoll_event *event) {
  int flags = 0;
  for (int i = 0; i < event_proto.event_flags_size(); ++i) {
    EpollEvent::EpollEventFlag curr_flag = event_proto.event_flags(i);
    if (curr_flag == EpollEvent::PROTO_IN)
      flags |= EPOLLIN;
    else if (curr_flag == EpollEvent::PROTO_PRI)
      flags |= EPOLLPRI;
    else if (curr_flag == EpollEvent::PROTO_OUT)
      flags |= EPOLLOUT;
    else if (curr_flag == EpollEvent::PROTO_MSG)
      flags |= EPOLLMSG;
    else if (curr_flag == EpollEvent::PROTO_ERR)
      flags |= EPOLLERR;
    else if (curr_flag == EpollEvent::PROTO_HUP)
      flags |= EPOLLHUP;
    else if (curr_flag == EpollEvent::PROTO_RDHUP)
      flags |= EPOLLRDHUP;
    else if (curr_flag == EpollEvent::PROTO_WAKEUP)
      flags |= EPOLLWAKEUP;
    else if (curr_flag == EpollEvent::PROTO_ONESHOT)
      flags |= EPOLLONESHOT;
    else if (curr_flag == EpollEvent::PROTO_ET)
      flags |= EPOLLET;
  }
  event->events = flags;
  event->data.u64 = event_proto.data();
}

bool ConvertToEpollEventList(const struct epoll_event *events, int numevents,
                             EpollEventList *event_list) {
  if (!events || !event_list) return false;
  for (int i = 0; i < numevents; i++) {
    EpollEvent *event = event_list->add_events();
    ConvertToEpollEventProtobuf(&events[i], event);
  }
  return true;
}

bool ConvertToEpollEventStructs(const EpollEventList &event_list,
                                struct epoll_event *events, int *numevents) {
  if (!events) {
    return false;
  }
  *numevents = event_list.events().size();
  for (int i = 0; i < *numevents; ++i) {
    ConvertToEpollEvent(event_list.events(i), &events[i]);
  }
  return true;
}

EpollCtlArgs::EpollCtlOp ConvertToProtoOp(int host_op) {
  if (host_op == EPOLL_CTL_ADD)
    return EpollCtlArgs::PROTO_CTL_ADD;
  else if (host_op == EPOLL_CTL_DEL)
    return EpollCtlArgs::PROTO_CTL_DEL;
  else if (host_op == EPOLL_CTL_MOD)
    return EpollCtlArgs::PROTO_CTL_MOD;
  return EpollCtlArgs::UNSUPPORTED;
}

int ConvertToHostOp(EpollCtlArgs::EpollCtlOp proto_op) {
  if (proto_op == EpollCtlArgs::PROTO_CTL_ADD)
    return EPOLL_CTL_ADD;
  else if (proto_op == EpollCtlArgs::PROTO_CTL_DEL)
    return EPOLL_CTL_DEL;
  else if (proto_op == EpollCtlArgs::PROTO_CTL_MOD)
    return EPOLL_CTL_MOD;
  return -1;
}

bool ConvertToEpollCtlArgsProtobuf(int epfd, int op, int fd,
                                   struct epoll_event *event,
                                   EpollCtlArgs *args) {
  if ((!event && op != EPOLL_CTL_DEL) || !args) return false;
  args->set_epfd(epfd);
  args->set_op(ConvertToProtoOp(op));
  args->set_hostfd(fd);
  EpollEvent *event_proto = args->mutable_event();
  if (event) ConvertToEpollEventProtobuf(event, event_proto);
  return true;
}

bool ConvertToEpollWaitArgsProtobuf(int epfd, int maxevents, int timeout,
                                    EpollWaitArgs *args) {
  if (!args) return false;
  args->set_epfd(epfd);
  args->set_maxevents(maxevents);
  args->set_timeout(timeout);
  return true;
}

// IfAddr conversion functions.
int FromProtoIffFlags(const IfAddrProto &in) {
  int flags = 0;
  for (int i = 0; i < in.ifa_flags().size(); ++i) {
    IfAddrProto::IfAddrFlag curr_flag = in.ifa_flags(i);
    if (curr_flag == IfAddrProto::PROTO_UP) flags |= IFF_UP;
    if (curr_flag == IfAddrProto::PROTO_BROADCAST) flags |= IFF_BROADCAST;
    if (curr_flag == IfAddrProto::PROTO_DEBUG) flags |= IFF_DEBUG;
    if (curr_flag == IfAddrProto::PROTO_LOOPBACK) flags |= IFF_LOOPBACK;
    if (curr_flag == IfAddrProto::PROTO_POINTOPOINT) flags |= IFF_POINTOPOINT;
    if (curr_flag == IfAddrProto::PROTO_NOTRAILERS) flags |= IFF_NOTRAILERS;
    if (curr_flag == IfAddrProto::PROTO_RUNNING) flags |= IFF_RUNNING;
    if (curr_flag == IfAddrProto::PROTO_NOARP) flags |= IFF_NOARP;
    if (curr_flag == IfAddrProto::PROTO_PROMISC) flags |= IFF_PROMISC;
    if (curr_flag == IfAddrProto::PROTO_ALLMULTI) flags |= IFF_ALLMULTI;
    if (curr_flag == IfAddrProto::PROTO_MULTICAST) flags |= IFF_MULTICAST;
  }
  return flags;
}

void ToProtoIffFlags(int flags, IfAddrProto *out) {
  if (flags & IFF_UP) out->add_ifa_flags(IfAddrProto::PROTO_UP);
  if (flags & IFF_BROADCAST) out->add_ifa_flags(IfAddrProto::PROTO_BROADCAST);
  if (flags & IFF_DEBUG) out->add_ifa_flags(IfAddrProto::PROTO_DEBUG);
  if (flags & IFF_LOOPBACK) out->add_ifa_flags(IfAddrProto::PROTO_LOOPBACK);
  if (flags & IFF_POINTOPOINT)
    out->add_ifa_flags(IfAddrProto::PROTO_POINTOPOINT);
  if (flags & IFF_NOTRAILERS) out->add_ifa_flags(IfAddrProto::PROTO_NOTRAILERS);
  if (flags & IFF_RUNNING) out->add_ifa_flags(IfAddrProto::PROTO_RUNNING);
  if (flags & IFF_NOARP) out->add_ifa_flags(IfAddrProto::PROTO_NOARP);
  if (flags & IFF_PROMISC) out->add_ifa_flags(IfAddrProto::PROTO_PROMISC);
  if (flags & IFF_ALLMULTI) out->add_ifa_flags(IfAddrProto::PROTO_ALLMULTI);
  if (flags & IFF_MULTICAST) out->add_ifa_flags(IfAddrProto::PROTO_MULTICAST);
}

bool ConvertToIfAddrs(const IfAddrsProto &in, struct ifaddrs **out) {
  if (!out) return false;

  struct ifaddrs *prev_ifaddr = nullptr;
  for (int i = 0; i < in.ifaddrs().size(); ++i) {
    const IfAddrProto &ifaddr_proto = in.ifaddrs(i);
    struct ifaddrs *ifaddr_node =
        static_cast<struct ifaddrs *>(calloc(1, sizeof(struct ifaddrs)));
    if (ifaddr_node == nullptr) {
      FreeDeserializedIfAddrs(*out);
      *out = nullptr;
      return false;
    }
    // all struct sockbuf * fields are initialized to nullptr by default
    ifaddr_node->ifa_name = strdup(ifaddr_proto.ifa_name().c_str());
    ifaddr_node->ifa_flags = FromProtoIffFlags(ifaddr_proto);
    if ((ifaddr_proto.has_ifa_addr() &&
         !ConvertToSockaddr(ifaddr_proto.ifa_addr(), &ifaddr_node->ifa_addr)) ||
        (ifaddr_proto.has_ifa_netmask() &&
         !ConvertToSockaddr(ifaddr_proto.ifa_netmask(),
                            &ifaddr_node->ifa_netmask)) ||
        (ifaddr_proto.has_ifa_ifu() &&
         !ConvertToSockaddr(ifaddr_proto.ifa_ifu(),
                            &((ifaddr_node->ifa_ifu).ifu_dstaddr)))) {
      FreeDeserializedIfAddrs(*out);
      *out = nullptr;
      return false;
    }
    if (!prev_ifaddr) {
      *out = ifaddr_node;
    } else {
      prev_ifaddr->ifa_next = ifaddr_node;
    }
    prev_ifaddr = ifaddr_node;
  }
  return true;
}

// Returns true if the sa_family is AF_INET or AF_INET6, false otherwise.
bool IpCompliant(const struct sockaddr *addr) {
  return (addr->sa_family == AF_INET) || (addr->sa_family == AF_INET6);
}

bool ConvertToIfAddrsProtobuf(const struct ifaddrs *in, IfAddrsProto *out) {
  if (!in || !out) return false;

  for (const struct ifaddrs *curr = in; curr != nullptr;
       curr = curr->ifa_next) {
    // If the entry is of a format we don't support, don't include it.
    if (!IfAddrSupported(curr)) continue;
    IfAddrProto *ifaddr_proto = out->add_ifaddrs();
    ifaddr_proto->set_ifa_name(curr->ifa_name);
    ToProtoIffFlags(curr->ifa_flags, ifaddr_proto);
    // It is possible for ifa_addr and ifa_netmask to be NULL, in which case,
    // they will not be included in the protobuf
    if ((curr->ifa_addr &&
         !ConvertToSockaddrProtobuf(curr->ifa_addr,
                                    ifaddr_proto->mutable_ifa_addr())) ||
        (curr->ifa_netmask &&
         !ConvertToSockaddrProtobuf(curr->ifa_netmask,
                                    ifaddr_proto->mutable_ifa_netmask())) ||
        (curr->ifa_ifu.ifu_dstaddr &&
         !ConvertToSockaddrProtobuf(curr->ifa_ifu.ifu_dstaddr,
                                    ifaddr_proto->mutable_ifa_ifu()))) {
      // If any of these conversions doesn't pan out, e.g. because of a protocol
      // that is unavailable, simply don't include it with the rest of the
      // protobuf
      return false;
    }
  }
  return true;
}
}  // namespace

bool SerializeAddrinfo(const struct addrinfo *in, std::string *out) {
  AddrinfosProto addrinfo_protobuf;
  if (!in) return addrinfo_protobuf.SerializeToString(out);  // empty addrinfo
  return ConvertToAddrinfoProtobuf(in, &addrinfo_protobuf) &&
         addrinfo_protobuf.SerializeToString(out);
}

bool DeserializeAddrinfo(const std::string *in, struct addrinfo **out) {
  AddrinfosProto addrinfo_protobuf;
  if (!addrinfo_protobuf.ParseFromString(*in)) return false;
  if (addrinfo_protobuf.addrinfos_size() == 0) {
    *out = nullptr;  // empty addrinfo
    return true;
  }
  return ConvertToAddrinfo(&addrinfo_protobuf, out);
}

void FreeDeserializedAddrinfo(struct addrinfo *in) {
  struct addrinfo *prev_info = nullptr;
  for (struct addrinfo *info = in; info != nullptr; info = info->ai_next) {
    if (prev_info) free(prev_info);
    if (info->ai_addr) free(info->ai_addr);
    if (info->ai_canonname) free(info->ai_canonname);
    prev_info = info;
  }
  if (prev_info) free(prev_info);
}

bool SerializeEpollCtlArgs(int epfd, int op, int fd, struct epoll_event *event,
                           char **out, size_t *len) {
  if (!out || !len) return false;
  EpollCtlArgs args_proto;
  if (ConvertToEpollCtlArgsProtobuf(epfd, op, fd, event, &args_proto)) {
    *len = args_proto.ByteSizeLong();
    // The caller is responsible for freeing the memory allocated by malloc.
    *out = static_cast<char *>(malloc(*len));
    return args_proto.SerializeToArray(*out, *len);
  }
  return false;
}

bool DeserializeEpollCtlArgs(absl::string_view in, int *epfd, int *op, int *fd,
                             struct epoll_event *event) {
  if (!epfd || !op || !fd || (!event && *op == EPOLL_CTL_DEL)) return false;
  EpollCtlArgs args_proto;
  if (!args_proto.ParseFromArray(in.data(), in.length())) return false;
  *epfd = args_proto.epfd();
  *op = ConvertToHostOp(args_proto.op());
  *fd = args_proto.hostfd();
  if (args_proto.has_event()) ConvertToEpollEvent(args_proto.event(), event);
  return true;
}

bool SerializeEpollWaitArgs(int epfd, int maxevents, int timeout, char **out,
                            size_t *len) {
  if (!out || !len) return false;
  EpollWaitArgs args_proto;
  if (ConvertToEpollWaitArgsProtobuf(epfd, maxevents, timeout, &args_proto)) {
    *len = args_proto.ByteSizeLong();
    // The caller is responsible for freeing the memory allocated below.
    *out = static_cast<char *>(malloc(*len));
    return args_proto.SerializeToArray(*out, *len);
  }
  return false;
}

bool DeserializeEpollWaitArgs(absl::string_view in, int *epfd, int *maxevents,
                              int *timeout) {
  if (!epfd || !maxevents) return false;
  EpollWaitArgs args_proto;
  if (!args_proto.ParseFromArray(in.data(), in.length())) return false;
  *epfd = args_proto.epfd();
  *maxevents = args_proto.maxevents();
  *timeout = args_proto.timeout();
  return true;
}

bool SerializeEvents(const struct epoll_event *events, int numevents,
                     char **out, size_t *len) {
  if (!events || !out) return false;
  EpollEventList event_list_proto;
  if (ConvertToEpollEventList(events, numevents, &event_list_proto)) {
    *len = event_list_proto.ByteSizeLong();
    // The caller is responsible for freeing the memory allocated below.
    *out = static_cast<char *>(malloc(*len));
    return event_list_proto.SerializeToArray(*out, *len);
  }
  return false;
}

bool DeserializeEvents(absl::string_view in, struct epoll_event *events,
                       int *numevents) {
  if (!events || !numevents) return false;
  EpollEventList event_list_proto;
  if (!event_list_proto.ParseFromArray(in.data(), in.length())) return false;
  return ConvertToEpollEventStructs(event_list_proto, events, numevents);
}

bool SerializeIfAddrs(const struct ifaddrs *in, char **out, size_t *len) {
  IfAddrsProto ifaddrs_proto;
  if (!out) return false;

  if (!in || ConvertToIfAddrsProtobuf(in, &ifaddrs_proto)) {
    *out = static_cast<char *>(malloc(ifaddrs_proto.ByteSizeLong()));
    *len = ifaddrs_proto.ByteSizeLong();
    return ifaddrs_proto.SerializeToArray(*out, ifaddrs_proto.ByteSizeLong());
  }
  return false;
}

bool DeserializeIfAddrs(absl::string_view in, struct ifaddrs **out) {
  IfAddrsProto ifaddrs_proto;
  if (!ifaddrs_proto.ParseFromArray(in.data(), in.length())) return false;
  if (ifaddrs_proto.ifaddrs_size() == 0) {
    *out = nullptr;
    return true;
  }
  return ConvertToIfAddrs(ifaddrs_proto, out);
}

void FreeDeserializedIfAddrs(struct ifaddrs *ifa) {
  struct ifaddrs *curr = ifa;
  while (curr != nullptr) {
    struct ifaddrs *next = curr->ifa_next;
    free(curr->ifa_name);  // std::string allocated by strdup (which uses malloc)
    free(curr->ifa_addr);  // all sockaddrs are also heap allocated
    free(curr->ifa_netmask);
    free(curr->ifa_ifu.ifu_dstaddr);
    free(curr);
    curr = next;
  }
}

bool IfAddrSupported(const struct ifaddrs *entry) {
  if (entry->ifa_addr && !IpCompliant(entry->ifa_addr)) return false;
  if (entry->ifa_netmask && !IpCompliant(entry->ifa_netmask)) return false;
  if (entry->ifa_ifu.ifu_dstaddr && !IpCompliant(entry->ifa_ifu.ifu_dstaddr)) {
    return false;
  }
  return true;
}

}  // namespace asylo
