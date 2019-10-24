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

#ifndef ASYLO_PLATFORM_HOST_CALL_SERIALIZER_FUNCTIONS_H_
#define ASYLO_PLATFORM_HOST_CALL_SERIALIZER_FUNCTIONS_H_

#include <ifaddrs.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/inotify.h>
#include <sys/socket.h>

#include <queue>

#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/util/message.h"

namespace asylo {
namespace host_call {

// Deserializes a MessageReader containing serialized linked list of addrinfos
// into |*out|.
bool DeserializeAddrinfo(primitives::MessageReader *in, struct addrinfo **out,
                         void (*abort_handler)(const char *message));

// Deserializes a MessageReader containing serialized linked list of ifaddrs
// into |*out|.
bool DeserializeIfAddrs(primitives::MessageReader *in, struct ifaddrs **out,
                        void (*abort_handler)(const char *message));

// Serializes struct passwd on the MessageWriter provided.
bool SerializePasswd(primitives::MessageWriter *writer,
                     struct passwd *password);

// Serializes a native addrinfo linked list on the MessageWriter provided. The
// sockaddrs contained in |addrs| are converted to klinux_sockaddr before being
// pushed on the writer. Similarly, ai_flags, ai_family, ai_socktype are
// converted to their klinux values.
primitives::PrimitiveStatus SerializeAddrInfo(
    primitives::MessageWriter *writer, struct addrinfo *addrs,
    void (*abort_handler)(const char *message),
    bool explicit_klinux_conversion = false);

// Serializes a native ifaddrs linked list on the MessageWriter provided. The
// sockaddrs contained in |ifaddr_list| are converted to klinux_sockaddr before
// being pushed on the Writer. Similarly, ifa_flags are converted to klinux
// ifa_flags.
primitives::PrimitiveStatus SerializeIfAddrs(
    primitives::MessageWriter *writer, struct ifaddrs *ifaddr_list,
    void (*abort_handler)(const char *message),
    bool explicit_klinux_conversion = false);

// Returns true if all sockaddr fields are compatible with IPv4 or IPv6, false
// otherwise. The sockaddr fields in the ifaddrs struct may also be null.
// IfAddrSupported is exposed here since it is used in tests.
bool IsIfAddrSupported(const struct ifaddrs *entry);

// Frees up the ifaddrs that are allocated by enc_untrusted_getifaddrs() or by
// DeserializeIfAddrs.
void FreeDeserializedIfAddrs(struct ifaddrs *ifa);

// Serializes a buffer containing list of inotify event structs to the buffer
// |*out|. The caller is responsible for ownership of serialized events.
bool SerializenotifyEvents(const char *buf, size_t buf_len, char **out,
                           size_t *len);

// Deserializes a buffer containing list of inotify event structs into a
// queue of events owned by the caller.
bool DeserializeInotifyEvents(const char *buf, size_t buf_len,
                              std::queue<struct inotify_event *> *events);

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_SERIALIZER_FUNCTIONS_H_
