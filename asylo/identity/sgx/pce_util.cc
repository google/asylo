/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/identity/sgx/pce_util.h"

#include <openssl/bn.h>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/status.h"
#include "QuoteGeneration/psw/pce_wrapper/inc/sgx_pce.h"

namespace asylo {
namespace sgx {

constexpr size_t kRsa3072ModulusSize = 384;
constexpr size_t kRsa3072ExponentSize = 4;

absl::optional<uint8_t> AsymmetricEncryptionSchemeToPceCryptoSuite(
    AsymmetricEncryptionScheme asymmetric_encryption_scheme) {
  switch (asymmetric_encryption_scheme) {
    case RSA3072_OAEP:
      return static_cast<uint8_t>(PCE_ALG_RSA_OAEP_3072);
    case RSA2048_OAEP:
      ABSL_FALLTHROUGH_INTENDED;
    default:
      return absl::nullopt;
  }
}

absl::optional<uint8_t> SignatureSchemeToPceSignatureScheme(
    SignatureScheme signature_scheme) {
  switch (signature_scheme) {
    case ECDSA_P256_SHA256:
      return static_cast<uint8_t>(PCE_NIST_P256_ECDSA_SHA256);
    default:
      return absl::nullopt;
  }
}

StatusOr<bssl::UniquePtr<RSA>> ParseRsa3072PublicKey(
    absl::Span<const uint8_t> public_key) {
  if (public_key.size() != kRsa3072ModulusSize + kRsa3072ExponentSize) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("Invalid public key size: ", public_key.size()));
  }

  bssl::UniquePtr<BIGNUM> modulus(BN_new());
  if (!modulus) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  bssl::UniquePtr<BIGNUM> exponent(BN_new());
  if (!exponent) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  bssl::UniquePtr<RSA> rsa(RSA_new());
  if (!rsa) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  BN_bin2bn(public_key.data(), /*len=*/kRsa3072ModulusSize, modulus.get());
  BN_bin2bn(public_key.data() + kRsa3072ModulusSize,
            /*len=*/kRsa3072ExponentSize, exponent.get());

  // Takes ownership of |modulus| and |exponent|.
  if (RSA_set0_key(rsa.get(), modulus.release(), exponent.release(),
                   /*d=*/nullptr) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return rsa;
}

StatusOr<std::vector<uint8_t>> SerializeRsa3072PublicKey(RSA *rsa) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

}  // namespace sgx
}  // namespace asylo
