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

#include "asylo/platform/arch/include/trusted/host_calls.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t flip_endian_32(uint32_t u32_in) {
  const char *in = reinterpret_cast<const char *>(&u32_in);
  char out[4];
  out[0] = in[3];
  out[1] = in[2];
  out[2] = in[1];
  out[3] = in[0];
  return *reinterpret_cast<uint32_t *>(out);
}

static inline uint16_t flip_endian_16(uint16_t u16_in) {
  const char *in = reinterpret_cast<const char *>(&u16_in);
  char out[2];
  out[0] = in[1];
  out[1] = in[0];
  return *reinterpret_cast<uint16_t *>(out);
}

uint32_t htonl(uint32_t hostlong) {
#ifdef __LITTLE_ENDIAN
  return flip_endian_32(hostlong);
#endif
  return hostlong;
}

uint16_t htons(uint16_t hostshort) {
#ifdef __LITTLE_ENDIAN
  return flip_endian_16(hostshort);
#endif
  return hostshort;
}

uint32_t ntohl(uint32_t netlong) {
#ifdef __LITTLE_ENDIAN
  return flip_endian_32(netlong);
#endif
  return netlong;
}

uint16_t ntohs(uint16_t netshort) {
#ifdef __LITTLE_ENDIAN
  return flip_endian_16(netshort);
#endif
  return netshort;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  return enc_untrusted_inet_ntop(af, src, dst, size);
}

int inet_pton(int af, const char *src, void *dst) {
  return enc_untrusted_inet_pton(af, src, dst);
}

#ifdef __cplusplus
}  // extern "C"
#endif
