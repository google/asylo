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

#include "absl/base/macros.h"
#include "QuoteGeneration/psw/pce_wrapper/inc/sgx_pce.h"

namespace asylo {
namespace sgx {

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

}  // namespace sgx
}  // namespace asylo
