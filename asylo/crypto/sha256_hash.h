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

#include <openssl/base.h>

#include <vector>

#include "asylo/crypto/hash_interface.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"

namespace asylo {

// Sha256Hash implements HashInterface for the SHA-256 hash function.
class Sha256Hash final : public HashInterface {
 public:
  Sha256Hash();
  ~Sha256Hash() override;

  // From HashInterface.
  HashAlgorithm GetHashAlgorithm() const override;
  size_t DigestSize() const override;
  void Init() override;
  void Update(ByteContainerView data) override;
  Status CumulativeHash(std::vector<uint8_t> *digest) const override;

 private:
  EVP_MD_CTX *context_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA256_HASH_H_
