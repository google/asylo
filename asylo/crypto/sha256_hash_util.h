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

#ifndef ASYLO_CRYPTO_SHA256_HASH_UTIL_H_
#define ASYLO_CRYPTO_SHA256_HASH_UTIL_H_

#include <cstdint>
#include <string>

#include "asylo/crypto/sha256_hash.pb.h"

namespace asylo {
constexpr uint32_t kSha256Size = 32;

// Parses a Sha256Hash from a hex string. The hex string must be exactly
// kSha256Size*2 characters long, and must consist of only hex digits.
bool Sha256HashFromHexString(const std::string &hex, Sha256HashProto *h);

// Converts a Sha256Hash to a hex string.
void Sha256HashToHexString(const Sha256HashProto &h, std::string *str);

// Compares two Sha256Hash protobufs for equality.
bool operator==(const Sha256HashProto &lhs, const Sha256HashProto &rhs);

// Compares two Sha256Hash protobufs for inequality.
bool operator!=(const Sha256HashProto &lhs, const Sha256HashProto &rhs);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA256_HASH_UTIL_H_
