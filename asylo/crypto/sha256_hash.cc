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

namespace asylo {

Sha256Hash::Sha256Hash() { Init(); }

HashAlgorithm Sha256Hash::Algorithm() const { return HashAlgorithm::SHA256; }

size_t Sha256Hash::DigestSize() const { return SHA256_DIGEST_LENGTH; }

void Sha256Hash::Init() { SHA256_Init(&context_); }

void Sha256Hash::Update(const void *data, size_t len) {
  SHA256_Update(&context_, data, len);
}

std::string Sha256Hash::CumulativeHash() const {
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  uint8_t digest_bytes[SHA256_DIGEST_LENGTH];
  SHA256_CTX context_snapshot = context_;
  SHA256_Final(digest_bytes, &context_snapshot);
  return std::string(reinterpret_cast<char *>(digest_bytes), SHA256_DIGEST_LENGTH);
}

}  // namespace asylo
