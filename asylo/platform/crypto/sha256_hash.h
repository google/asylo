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

#ifndef ASYLO_PLATFORM_CRYPTO_SHA256_HASH_H_
#define ASYLO_PLATFORM_CRYPTO_SHA256_HASH_H_

#include <openssl/sha.h>

#include <string>

#include "asylo/platform/crypto/hash_interface.h"

namespace asylo {

// Sha256Hash implements HashInterface for the SHA-256 hash function.
class Sha256Hash final : public HashInterface {
 public:
  Sha256Hash();

  // From HashInterface.
  HashAlgorithm Algorithm() const override;
  size_t DigestSize() const override;
  void Init() override;
  void Update(const void *data, size_t len) override;
  std::string CumulativeHash() override;

 private:
  SHA256_CTX context_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CRYPTO_SHA256_HASH_H_
