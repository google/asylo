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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_PCE_UTIL_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_PCE_UTIL_H_

#include <openssl/base.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

ABSL_CONST_INIT extern const size_t kRsa3072SerializedExponentSize;
ABSL_CONST_INIT extern const size_t kEcdsaP256SignatureSize;

// The hash used by the PCE when encrypting the PPID with RSA-OAEP.
ABSL_CONST_INIT extern const HashAlgorithm kPpidRsaOaepHashAlgorithm;

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

// Returns the number of bytes in the encrypted output for |scheme|.
StatusOr<uint32_t> GetEncryptedDataSize(AsymmetricEncryptionScheme scheme);

// Converts a SignatureScheme to an equivalent signature scheme representation
// used by the PCE.
absl::optional<uint8_t> SignatureSchemeToPceSignatureScheme(
    SignatureScheme signature_scheme);

// Converts a PCE signature scheme to an equivalent SignatureScheme value.
SignatureScheme PceSignatureSchemeToSignatureScheme(
    uint8_t pce_signature_scheme);

// Creates a Signature proto from a PCK-generated ECDSA-P256-SHA256 signature
// |pck_signature|. The input |pck_signature| is expected to be a 64-byte buffer
// with the following format:
//
//   r [32] || s [32]
//
// where the r and s parameters are in big-endian format.
StatusOr<Signature> CreateSignatureFromPckEcdsaP256Sha256Signature(
    ByteContainerView pck_signature);

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

// Creates a serialized payload for the given PPID encryption key in |ppidek|.
// The serialized payload is created according to format defined by the PCE.
//
// Currently, only RSA-3072 keys are supported. See SerializeRsa3072PublicKey()
// for details on the serialization format.
//
// If the input is not an encryption key, or not of a supported key type,
// returns a non-OK Status.
StatusOr<std::vector<uint8_t>> SerializePpidek(
    const AsymmetricEncryptionKeyProto &ppidek);

// Creates and returns a REPORTDATA based on |ppidek| that is suitable for use
// in the PCE's GetPceInfo protocol.
StatusOr<Reportdata> CreateReportdataForGetPceInfo(
    const AsymmetricEncryptionKeyProto &ppidek);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_PCE_UTIL_H_
