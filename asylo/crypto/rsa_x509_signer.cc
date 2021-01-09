/*
 * Copyright 2020 Asylo authors
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

#include "asylo/crypto/rsa_x509_signer.h"

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <utility>

#include "absl/memory/memory.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {

StatusOr<std::unique_ptr<RsaX509Signer>> RsaX509Signer::CreateFromPem(
    ByteContainerView serialized_private_key, const EVP_MD* hash) {
  // The input bio object containing the serialized key.
  bssl::UniquePtr<BIO> private_key_bio(BIO_new_mem_buf(
      serialized_private_key.data(), serialized_private_key.size()));

  // Create a private key from the input PEM data.
  bssl::UniquePtr<RSA> private_key(PEM_read_bio_RSAPrivateKey(
      private_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!private_key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return absl::WrapUnique<RsaX509Signer>(
      new RsaX509Signer(std::move(private_key), hash));
}

int RsaX509Signer::KeySizeInBits() const {
  // RSA_size returns the number of bytes in the modulus, mutiply by 8 for bits
  return RSA_size(private_key_.get()) * 8;
}

StatusOr<CleansingVector<char>> RsaX509Signer::SerializeToPem() const {
  BIO *new_key_bio = BIO_new(BIO_s_mem());
  if (new_key_bio == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  bssl::UniquePtr<BIO> key_bio(new_key_bio);
  if (!PEM_write_bio_RSAPrivateKey(key_bio.get(), private_key_.get(),
                                   /*enc=*/nullptr, /*kstr=*/nullptr,
                                   /*klen=*/0,
                                   /*cb=*/nullptr, /*u=*/nullptr)) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  size_t key_data_size;
  const uint8_t* key_data = nullptr;
  if (BIO_mem_contents(key_bio.get(), &key_data, &key_data_size) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  CleansingVector<char> serialized_key(key_data, key_data + key_data_size);

  BIO_reset(key_bio.get());

  return serialized_key;
}

Status RsaX509Signer::SignX509(X509* x509) const {
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (EVP_PKEY_set1_RSA(evp_pkey.get(), private_key_.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  if (X509_sign(x509, evp_pkey.get(), hash_) == 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Status::OkStatus();
}

RsaX509Signer::RsaX509Signer(bssl::UniquePtr<RSA> private_key,
                             const EVP_MD* hash)
    : private_key_(std::move(private_key)), hash_(hash) {}

}  // namespace asylo
