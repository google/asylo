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

#ifndef ASYLO_PLATFORM_COMMON_BRIDGE_PROTO_SERIALIZER_H_
#define ASYLO_PLATFORM_COMMON_BRIDGE_PROTO_SERIALIZER_H_

#include "absl/strings/string_view.h"
#include "asylo/platform/common/bridge_proto_types.pb.h"

// This file provides a set of type definitions used both inside and outside the
// enclave.

namespace asylo {

constexpr int kIn6AddrNumBytes = 16;

bool SerializeAddrinfo(const struct addrinfo *in, std::string *out);

bool DeserializeAddrinfo(const std::string *in, struct addrinfo **out);

void FreeDeserializedAddrinfo(struct addrinfo *in);

bool SerializeIfAddrs(const struct ifaddrs *in, char **out, size_t *len);

bool DeserializeIfAddrs(absl::string_view in, struct ifaddrs **out);

void FreeDeserializedIfAddrs(struct ifaddrs *ifa);

// Returns true if all sockaddr fields are compatible with IPv4 or IPv6, false
// otherwise. The sockaddr fields in the ifaddrs struct may also be null.
// IfAddrSupported is exposed here since it is used in tests.
bool IfAddrSupported(const struct ifaddrs *entry);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_PROTO_SERIALIZER_H_
