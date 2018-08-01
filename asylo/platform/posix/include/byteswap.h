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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_BYTESWAP_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_BYTESWAP_H_


#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint16_t bswap_16(uint16_t n) { return __builtin_bswap16(n); }

static inline uint32_t bswap_32(uint32_t n) { return __builtin_bswap32(n); }

static inline uint64_t bswap_64(uint64_t n) { return __builtin_bswap64(n); }

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_BYTESWAP_H_
