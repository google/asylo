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
#include "asylo/util/statusor.h"

namespace asylo {

/// Returns a `Sha256HashProto` with the hash of the given |hash_hex|, or a
/// non-OK Status if the provided string is an invalid hex-encoded SHA-256 hash.
StatusOr<Sha256HashProto> CreateSha256HashProto(absl::string_view hash_hex);

/// Validates that |hash_proto| has a hash that is exactly 32 bytes.
Status ValidateSha256HashProto(const Sha256HashProto &hash_proto);

/// Compares two `Sha256HashProto` messages for equality.
bool operator==(const Sha256HashProto &lhs, const Sha256HashProto &rhs);

/// Compares two `Sha256HashProto` messages for inequality.
bool operator!=(const Sha256HashProto &lhs, const Sha256HashProto &rhs);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA256_HASH_UTIL_H_
