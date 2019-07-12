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

#include <openssl/base.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

ABSL_CONST_INIT extern const size_t kRsa3072SerializedExponentSize;

// This file contains utility functions related to Intel-defined protocols used
// by the Provisioning Certification Enclave (PCE).

// Converts an AsymmetricEncryptionScheme to an equivalent crypto suite
// representation used by the PCE.
absl::optional<uint8_t> AsymmetricEncryptionSchemeToPceCryptoSuite(
    AsymmetricEncryptionScheme asymmetric_encryption_scheme);

// Converts a PCE crypto suite to an equivalent AsymmetricEncryptionScheme
// value.
AsymmetricEncryptionScheme PceCryptoSuiteToAsymmetricEncryptionScheme(
    uint8_t pce_crypto_suite);

// Converts a SignatureScheme to an equivalent signature scheme representation
// used by the PCE.
absl::optional<uint8_t> SignatureSchemeToPceSignatureScheme(
    SignatureScheme signature_scheme);

// Converts a PCE signature scheme to an equivalent SignatureScheme value.
SignatureScheme PceSignatureSchemeToSignatureScheme(
    uint8_t pce_signature_scheme);

// Parses an RSA-3072 public key from |public_key|. The input |public_key| is
// expected to be a 388-byte buffer that contains a serialized key in the
// following format:
//
//   modulus [384] || public_exponent [4]
//
// where modulus and public_exponent are in big-endian format.
StatusOr<bssl::UniquePtr<RSA>> ParseRsa3072PublicKey(
    absl::Span<const uint8_t> public_key);

// Serializes the given RSA-3072 public key from |rsa| into a 388-byte buffer
// with the following format:
//
//   modulus [384] || public_exponent [4]
//
// where modulus and public_exponent are in big-endian format.
StatusOr<std::vector<uint8_t>> SerializeRsa3072PublicKey(const RSA *rsa);

// Creates a REPORTDATA based on |asymmetric_encryption_scheme| and |rsa| that
// is suitable for use in the PCE's GetPceInfo protocol.
StatusOr<Reportdata> CreateReportdataForGetPceInfo(
    AsymmetricEncryptionScheme asymmetric_encryption_scheme, const RSA *rsa);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_PCE_UTIL_H_
