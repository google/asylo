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

#include <queue>

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

bool SerializeRecvFromArgs(int sockfd, size_t len, int flags, char **out,
                           size_t *out_len);

bool DeserializeRecvFromArgs(absl::string_view in, int *sockfd, size_t *len,
                             int *flags);

bool SerializeRecvFromSrcAddr(struct sockaddr *src_addr, char **out,
                              size_t *out_len);

bool DeserializeRecvFromSrcAddr(absl::string_view in,
                                struct sockaddr **src_addr);

// Returns true if all sockaddr fields are compatible with IPv4 or IPv6, false
// otherwise. The sockaddr fields in the ifaddrs struct may also be null.
// IfAddrSupported is exposed here since it is used in tests.
bool IfAddrSupported(const struct ifaddrs *entry);

bool SerializeEpollCtlArgs(int epfd, int op, int fd, struct epoll_event *event,
                           char **out, size_t *len);

bool SerializeEpollWaitArgs(int epfd, int maxevents, int timeout, char **out,
                            size_t *len);

bool DeserializeEpollCtlArgs(absl::string_view in, int *epfd, int *op, int *fd,
                             struct epoll_event *event);

bool DeserializeEpollWaitArgs(absl::string_view in, int *epfd, int *maxevents,
                              int *timeout);

bool SerializeEvents(const struct epoll_event *events, int numevents,
                     char **out, size_t *len);

bool DeserializeEvents(absl::string_view in, struct epoll_event *events,
                       int *numevents);

bool SerializeInotifyAddWatchArgs(int fd, absl::string_view pathname,
                                  uint32_t mask, char **out, size_t *len);

bool SerializeInotifyRmWatchArgs(int fd, int wd, char **out, size_t *len);

bool DeserializeInotifyAddWatchArgs(absl::string_view in, int *fd,
                                    char **pathname, uint32_t *mask);

bool DeserializeInotifyRmWatchArgs(absl::string_view in, int *fd, int *wd);

bool SerializeInotifyEvents(char *buf, size_t buf_len, char **out, size_t *len);

bool DeserializeInotifyEvents(absl::string_view in,
                              std::queue<struct inotify_event *> *events);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_PROTO_SERIALIZER_H_
