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

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string>

#include "asylo/platform/common/bridge_proto_serializer.h"

namespace asylo {
namespace {

bool ConvertToSockaddr(const SockaddrProto *in, struct sockaddr **out) {
  if (!in || !out) return false;

  struct sockaddr *sock;
  if (in->sa_family() == AF_INET6) {  // IPv6
    sock = static_cast<struct sockaddr *>(malloc(sizeof(struct sockaddr_in6)));
  } else if (in->sa_family() == AF_INET) {  // IPv4
    sock = static_cast<struct sockaddr *>(malloc(sizeof(struct sockaddr_in)));
  } else {
    return false;  // unsupported sa_family
  }
  if (!sock) return false;

  sock->sa_family = in->sa_family();
  memcpy(sock->sa_data, in->sa_data().c_str(), in->sa_data().length());
  *out = sock;
  return true;
}

bool ConvertToSockaddrProtobuf(const struct sockaddr *in, SockaddrProto *out) {
  if (!in || !out) return false;

  size_t data_len;
  if (in->sa_family == AF_INET6) {  // IPv6
    data_len = sizeof(struct sockaddr_in6) - sizeof(in->sa_family);
  } else if (in->sa_family == AF_INET) {  // IPv4
    data_len = sizeof(struct sockaddr_in) - sizeof(in->sa_family);
  } else {
    return false;  // unsupported sa_family
  }

  out->set_sa_family(in->sa_family);
  out->set_sa_data(std::string(in->sa_data, data_len));
  return true;
}

bool SetAddrinfoCanonname(const std::string *canonname, struct addrinfo *info) {
  char *ai_canonname = static_cast<char *>(malloc(canonname->length()));
  if (ai_canonname == nullptr) return false;
  memcpy(ai_canonname, canonname->c_str(), canonname->length());
  info->ai_canonname = ai_canonname;
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
        !ConvertToSockaddr(&info_proto.ai_addr(), &info->ai_addr)) {
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

}  // namespace asylo
