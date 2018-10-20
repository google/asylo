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

#include "asylo/crypto/sha256_hash.h"

#include <openssl/sha.h>

#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"

namespace asylo {

Sha256Hash::Sha256Hash() { Init(); }

HashAlgorithm Sha256Hash::GetHashAlgorithm() const {
  return HashAlgorithm::SHA256;
}

size_t Sha256Hash::DigestSize() const { return SHA256_DIGEST_LENGTH; }

void Sha256Hash::Init() { SHA256_Init(&context_); }

void Sha256Hash::Update(ByteContainerView data) {
  SHA256_Update(&context_, data.data(), data.size());
}

Status Sha256Hash::CumulativeHash(std::vector<uint8_t> *digest) const {
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  SHA256_CTX context_snapshot = context_;
  digest->resize(SHA256_DIGEST_LENGTH);
  if (SHA256_Final(digest->data(), &context_snapshot) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Status::OkStatus();
}

}  // namespace asylo
