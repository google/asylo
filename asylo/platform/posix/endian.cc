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

#include <byteswap.h>
#include <endian.h>

#include <cstdint>

#if _BYTE_ORDER == _LITTLE_ENDIAN

uint16_t htobe16(uint16_t host_16bits) { return bswap_16(host_16bits); }
uint16_t htole16(uint16_t host_16bits) { return host_16bits; }
uint16_t be16toh(uint16_t big_endian_16bits) {
  return bswap_16(big_endian_16bits);
}
uint16_t le16toh(uint16_t little_endian_16bits) { return little_endian_16bits; }

uint32_t htobe32(uint32_t host_32bits) { return bswap_32(host_32bits); }
uint32_t htole32(uint32_t host_32bits) { return host_32bits; }
uint32_t be32toh(uint32_t big_endian_32bits) {
  return bswap_32(big_endian_32bits);
}
uint32_t le32toh(uint32_t little_endian_32bits) { return little_endian_32bits; }

uint64_t htobe64(uint64_t host_64bits) { return bswap_64(host_64bits); }
uint64_t htole64(uint64_t host_64bits) { return host_64bits; }
uint64_t be64toh(uint64_t big_endian_64bits) {
  return bswap_64(big_endian_64bits);
}
uint64_t le64toh(uint64_t little_endian_64bits) { return little_endian_64bits; }

#else  // _BYTE_ORDER == _LITTLE_ENDIAN

uint16_t htobe16(uint16_t host_16bits) { return host_16bits; }
uint16_t htole16(uint16_t host_16bits) { return bswap_16(host_16bits); }
uint16_t be16toh(uint16_t big_endian_16bits) { return big_endian_16bits; }
uint16_t le16toh(uint16_t little_endian_16bits) {
  return bswap_16(little_endian_16bits);
}

uint32_t htobe32(uint32_t host_32bits) { return host_32bits; }
uint32_t htole32(uint32_t host_32bits) { return bswap_32(host_32bits); }
uint32_t be32toh(uint32_t big_endian_32bits) { return big_endian_32bits; }
uint32_t le32toh(uint32_t little_endian_32bits) {
  return bswap_32(little_endian_32bits);
}

uint64_t htobe64(uint64_t host_64bits) { return host_64bits; }
uint64_t htole64(uint64_t host_64bits) { return bswap_64(host_64bits); }
uint64_t be64toh(uint64_t big_endian_64bits) { return big_endian_64bits; }
uint64_t le64toh(uint64_t little_endian_64bits) {
  return bswap_64(little_endian_64bits);
}

#endif
