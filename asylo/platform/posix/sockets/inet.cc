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

#include <arpa/inet.h>
#include <byteswap.h>

#include "asylo/platform/host_call/trusted/host_calls.h"

extern "C" {

uint32_t htonl(uint32_t hostlong) {
#ifdef __LITTLE_ENDIAN
  return bswap_32(hostlong);
#else
  return hostlong;
#endif
}

uint16_t htons(uint16_t hostshort) {
#ifdef __LITTLE_ENDIAN
  return bswap_16(hostshort);
#else
  return hostshort;
#endif
}

uint32_t ntohl(uint32_t netlong) {
#ifdef __LITTLE_ENDIAN
  return bswap_32(netlong);
#else
  return netlong;
#endif
}

uint16_t ntohs(uint16_t netshort) {
#ifdef __LITTLE_ENDIAN
  return bswap_16(netshort);
#else
  return netshort;
#endif
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  return enc_untrusted_inet_ntop(af, src, dst, size);
}

int inet_pton(int af, const char *src, void *dst) {
  return enc_untrusted_inet_pton(af, src, dst);
}

}  // extern "C"
