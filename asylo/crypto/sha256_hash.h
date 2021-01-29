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

#ifndef ASYLO_CRYPTO_SHA256_HASH_H_
#define ASYLO_CRYPTO_SHA256_HASH_H_

#include <openssl/evp.h>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha_hash.h"

namespace asylo {

#if __cplusplus >= 201703L
inline constexpr int kSha256DigestLength = 32;
#else
constexpr int kSha256DigestLength = 32;
#endif

struct Sha256HashOptions {
  static constexpr int kDigestLength = kSha256DigestLength;
  static constexpr HashAlgorithm kHashAlgorithm = HashAlgorithm::SHA256;
  static const EVP_MD *EvpMd() { return EVP_sha256(); }
};

using Sha256Hash = ShaHash<Sha256HashOptions>;

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA256_HASH_H_
