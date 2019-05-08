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

#ifndef ASYLO_IDENTITY_SGX_PCE_UTIL_H_
#define ASYLO_IDENTITY_SGX_PCE_UTIL_H_

#include <cstdint>

#include "absl/types/optional.h"
#include "asylo/crypto/algorithms.pb.h"

namespace asylo {
namespace sgx {

// This file contains utility functions related to Intel-defined protocols used
// by the Provisioning Certification Enclave (PCE).

// Converts an AsymmetricEncryptionScheme to an equivalent crypto suite
// representation used by the PCE.
absl::optional<uint8_t> AsymmetricEncryptionSchemeToPceCryptoSuite(
    AsymmetricEncryptionScheme asymmetric_encryption_scheme);

// Converts an AsymmetricEncryptionScheme to an equivalent signature scheme
// representation used by the PCE.
absl::optional<uint8_t> SignatureSchemeToPceSignatureScheme(
    SignatureScheme signature_scheme);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_PCE_UTIL_H_
