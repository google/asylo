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

#include <openssl/base.h>
#include <openssl/digest.h>

#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"

namespace asylo {

Sha256Hash::Sha256Hash() : context_(CHECK_NOTNULL(EVP_MD_CTX_new())) { Init(); }

Sha256Hash::~Sha256Hash() { EVP_MD_CTX_free(context_); }

HashAlgorithm Sha256Hash::GetHashAlgorithm() const {
  return HashAlgorithm::SHA256;
}

size_t Sha256Hash::DigestSize() const { return EVP_MD_size(EVP_sha256()); }

void Sha256Hash::Init() {
  EVP_MD_CTX_cleanup(context_);
  EVP_DigestInit(context_, EVP_sha256());
}

void Sha256Hash::Update(ByteContainerView data) {
  EVP_DigestUpdate(context_, data.data(), data.size());
}

Status Sha256Hash::CumulativeHash(std::vector<uint8_t> *digest) const {
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  bssl::UniquePtr<EVP_MD_CTX> context_snapshot(EVP_MD_CTX_new());
  if (context_snapshot == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  EVP_MD_CTX_init(context_snapshot.get());
  if (EVP_MD_CTX_copy_ex(context_snapshot.get(), context_) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  digest->resize(DigestSize());
  unsigned int digest_len;
  if (EVP_DigestFinal(context_snapshot.get(), digest->data(), &digest_len) !=
          1 ||
      digest_len != DigestSize()) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Status::OkStatus();
}

}  // namespace asylo
