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
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {

StatusOr<std::unique_ptr<RsaX509Signer>> RsaX509Signer::CreateFromPem(
    ByteContainerView serialized_private_key,
    SignatureAlgorithm signature_algorithm) {
  // The input bio object containing the serialized key.
  bssl::UniquePtr<BIO> private_key_bio(BIO_new_mem_buf(
      serialized_private_key.data(), serialized_private_key.size()));

  // Create a private key from the input PEM data.
  bssl::UniquePtr<RSA> private_key(PEM_read_bio_RSAPrivateKey(
      private_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!private_key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return absl::WrapUnique<RsaX509Signer>(
      new RsaX509Signer(std::move(private_key), signature_algorithm));
}

int RsaX509Signer::KeySizeInBits() const {
  // RSA_size returns the number of bytes in the modulus, mutiply by 8 for bits
  return RSA_size(private_key_.get()) * 8;
}

StatusOr<std::string> RsaX509Signer::SerializePublicKeyToDer() const {
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (EVP_PKEY_set1_RSA(evp_pkey.get(), private_key_.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  CBB buffer;
  if (!CBB_init(&buffer, /*initial_capacity=*/0) ||
      !EVP_marshal_public_key(&buffer, evp_pkey.get())) {
    CBB_cleanup(&buffer);
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  uint8_t* key_data;
  size_t key_data_size;
  CBB_finish(&buffer, &key_data, &key_data_size);
  bssl::UniquePtr<uint8_t> deleter(key_data);

  return std::string(reinterpret_cast<char*>(key_data), key_data_size);
}

StatusOr<CleansingVector<char>> RsaX509Signer::SerializeToPem() const {
  BIO* new_key_bio = BIO_new(BIO_s_mem());
  if (new_key_bio == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  bssl::UniquePtr<BIO> key_bio(new_key_bio);
  if (!PEM_write_bio_RSAPrivateKey(key_bio.get(), private_key_.get(),
                                   /*enc=*/nullptr, /*kstr=*/nullptr,
                                   /*klen=*/0,
                                   /*cb=*/nullptr, /*u=*/nullptr)) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  size_t key_data_size;
  const uint8_t* key_data = nullptr;
  if (BIO_mem_contents(key_bio.get(), &key_data, &key_data_size) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  CleansingVector<char> serialized_key(key_data, key_data + key_data_size);

  BIO_reset(key_bio.get());

  return serialized_key;
}

Status RsaX509Signer::SignX509(X509* x509) const {
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (EVP_PKEY_set1_RSA(evp_pkey.get(), private_key_.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  EVP_MD_CTX hash;
  EVP_MD_CTX_init(&hash);
  switch (signature_algorithm_) {
    case RSASSA_PSS_WITH_SHA384: {
      EVP_PKEY_CTX* pkey_ctx;
      if (!EVP_DigestSignInit(&hash, &pkey_ctx, EVP_sha384(), /*e=*/nullptr,
                              evp_pkey.get()) ||
          !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
          !EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha384()) ||
          !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, 0x30)) {
        return Status(absl::StatusCode::kInternal, BsslLastErrorString());
      }
      break;
    }
  }

  if (X509_sign_ctx(x509, &hash) == 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status RsaX509Signer::SignX509Req(X509_REQ* x509_req) const {
  return absl::UnimplementedError("SignX509Req unsupported for RsaX509Signer");
}

RsaX509Signer::RsaX509Signer(bssl::UniquePtr<RSA> private_key,
                             SignatureAlgorithm signature_algorithm)
    : private_key_(std::move(private_key)),
      signature_algorithm_(signature_algorithm) {}

}  // namespace asylo
