/*
 * Copyright 2021 Asylo authors
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
 */

#ifndef ASYLO_CRYPTO_SHA384_HASH_H_
#define ASYLO_CRYPTO_SHA384_HASH_H_

#include <openssl/evp.h>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha_hash.h"

namespace asylo {

struct Sha384HashOptions {
  static constexpr int kDigestLength = 48;
  static constexpr HashAlgorithm kHashAlgorithm = HashAlgorithm::SHA384;
  static const EVP_MD *EvpMd() { return EVP_sha384(); }
};

using Sha384Hash = ShaHash<Sha384HashOptions>;

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA384_HASH_H_
