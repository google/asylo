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

#ifndef ASYLO_CRYPTO_SHA_HASH_H_
#define ASYLO_CRYPTO_SHA_HASH_H_

#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/evp.h>

#include <cstdint>
#include <vector>

#include "absl/status/status.h"
#include "asylo/crypto/hash_interface.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An implementation of HashInterface for SHA hash algorithms.

/* HashOptions must be a struct that contains the following fields:
 *   int kDigestLength - the output length of the hash, in bytes.
 *   HashAlgortihm kHashAlgorithm - the associated enum value in HashAlgorithm.
 *   const EVP_MD* EvpMd() - the BoringSSL structure used to implement the hash.
 */

template <typename HashOptions>
class ShaHash : public HashInterface {
 public:
  ShaHash() : context_(CHECK_NOTNULL(EVP_MD_CTX_new())) { Init(); }

  // From HashInterface.
  HashAlgorithm GetHashAlgorithm() const override {
    return HashOptions::kHashAlgorithm;
  };
  size_t DigestSize() const override { return HashOptions::kDigestLength; };
  void Init() override;
  void Update(ByteContainerView data) override {
    EVP_DigestUpdate(context_.get(), data.data(), data.size());
  }
  Status CumulativeHash(std::vector<uint8_t>* digest) const override;

  const EVP_MD* GetBsslHashFunction() { return HashOptions::EvpMd(); }

 private:
  bssl::UniquePtr<EVP_MD_CTX> context_;
};

template <typename HashOptions>
void ShaHash<HashOptions>::Init() {
  EVP_MD_CTX_cleanup(context_.get());
  EVP_DigestInit(context_.get(), HashOptions::EvpMd());
}

template <typename HashOptions>
Status ShaHash<HashOptions>::CumulativeHash(
    std::vector<uint8_t>* digest) const {
  // Do not finalize the internally stored hash context. Instead, finalize a
  // copy of the current context so that the current context can be updated in
  // future calls to Update.
  bssl::UniquePtr<EVP_MD_CTX> context_snapshot(EVP_MD_CTX_new());
  if (context_snapshot == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  if (EVP_MD_CTX_copy_ex(context_snapshot.get(), context_.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  digest->resize(DigestSize());
  unsigned int digest_len;
  if (EVP_DigestFinal(context_snapshot.get(), digest->data(), &digest_len) !=
          1 ||
      digest_len != DigestSize()) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA_HASH_H_
