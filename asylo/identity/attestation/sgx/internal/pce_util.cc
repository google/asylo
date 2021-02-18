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

#include "asylo/identity/attestation/sgx/internal/pce_util.h"

#include <openssl/bn.h>

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/rsa_oaep_encryption_key.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_constants.h"

namespace asylo {
namespace sgx {
namespace {

StatusOr<std::vector<uint8_t>> SerializeRsa3072Ppidek(
    const AsymmetricEncryptionKeyProto &ppidek) {
  std::unique_ptr<RsaOaepEncryptionKey> encryption_key;
  AsymmetricKeyEncoding encoding = ppidek.encoding();
  switch (encoding) {
    case AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER:
      ASYLO_ASSIGN_OR_RETURN(encryption_key,
                             RsaOaepEncryptionKey::CreateFromDer(
                                 ppidek.key(), kPpidRsaOaepHashAlgorithm));
      break;
    case AsymmetricKeyEncoding::ASYMMETRIC_KEY_PEM:
      ASYLO_ASSIGN_OR_RETURN(encryption_key,
                             RsaOaepEncryptionKey::CreateFromPem(
                                 ppidek.key(), kPpidRsaOaepHashAlgorithm));
      break;
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    absl::StrCat("Unsupported key encoding: ",
                                 ProtoEnumValueName(encoding)));
  }
  return SerializeRsa3072PublicKey(encryption_key->GetRsaPublicKey());
}

}  // namespace

const size_t kRsa3072SerializedExponentSize = 4;

// The size of an ECDSA-P256 signature. The r parameter is 32 bytes and the s
// parameter is 32 bytes, totaling 64 bytes.
const size_t kEcdsaP256SignatureSize = 64;

const HashAlgorithm kPpidRsaOaepHashAlgorithm = HashAlgorithm::SHA256;

absl::optional<uint8_t> AsymmetricEncryptionSchemeToPceCryptoSuite(
    AsymmetricEncryptionScheme asymmetric_encryption_scheme) {
  switch (asymmetric_encryption_scheme) {
    case RSA3072_OAEP:
      return static_cast<uint8_t>(PCE_ALG_RSA_OAEP_3072);
    case RSA2048_OAEP:
      ABSL_FALLTHROUGH_INTENDED;
    case UNKNOWN_ASYMMETRIC_ENCRYPTION_SCHEME:
      break;
  }

  return absl::nullopt;
}

AsymmetricEncryptionScheme PceCryptoSuiteToAsymmetricEncryptionScheme(
    uint8_t pce_crypto_suite) {
  switch (pce_crypto_suite) {
    case PCE_ALG_RSA_OAEP_3072:
      return RSA3072_OAEP;
  }

  return UNKNOWN_ASYMMETRIC_ENCRYPTION_SCHEME;
}

StatusOr<uint32_t> GetEncryptedDataSize(AsymmetricEncryptionScheme scheme) {
  switch (scheme) {
    case AsymmetricEncryptionScheme::RSA2048_OAEP:
      return 2048 / 8;
    case AsymmetricEncryptionScheme::RSA3072_OAEP:
      return 3072 / 8;
    case AsymmetricEncryptionScheme::UNKNOWN_ASYMMETRIC_ENCRYPTION_SCHEME:
      break;
  }

  return Status(
      absl::StatusCode::kInvalidArgument,
      absl::StrCat("Invalid encryption scheme: ", ProtoEnumValueName(scheme)));
}

absl::optional<uint8_t> SignatureSchemeToPceSignatureScheme(
    SignatureScheme signature_scheme) {
  switch (signature_scheme) {
    case ECDSA_P256_SHA256:
      return static_cast<uint8_t>(PCE_NIST_P256_ECDSA_SHA256);
    case ECDSA_P384_SHA384:
    case UNKNOWN_SIGNATURE_SCHEME:
      break;
  }

  return absl::nullopt;
}

SignatureScheme PceSignatureSchemeToSignatureScheme(
    uint8_t pce_signature_scheme) {
  switch (pce_signature_scheme) {
    case PCE_NIST_P256_ECDSA_SHA256:
      return ECDSA_P256_SHA256;
  }

  return UNKNOWN_SIGNATURE_SCHEME;
}

StatusOr<Signature> CreateSignatureFromPckEcdsaP256Sha256Signature(
    ByteContainerView pck_signature) {
  if (pck_signature.size() != kEcdsaP256SignatureSize) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Signature is the wrong size for ECDSA-P256-SHA256: ",
                     pck_signature.size(), " (expected ",
                     kEcdsaP256SignatureSize, ")"));
  }

  Signature signature;
  signature.set_signature_scheme(SignatureScheme::ECDSA_P256_SHA256);

  EcdsaSignature *ecdsa_signature = signature.mutable_ecdsa_signature();
  ecdsa_signature->set_r(pck_signature.data(), 32);
  ecdsa_signature->set_s(pck_signature.data() + 32, 32);

  return signature;
}

StatusOr<bssl::UniquePtr<RSA>> ParseRsa3072PublicKey(
    absl::Span<const uint8_t> public_key) {
  if (public_key.size() !=
      kRsa3072ModulusSize + kRsa3072SerializedExponentSize) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Invalid public key size: ", public_key.size()));
  }

  bssl::UniquePtr<BIGNUM> modulus(BN_new());
  if (!modulus) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  bssl::UniquePtr<BIGNUM> exponent(BN_new());
  if (!exponent) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  bssl::UniquePtr<RSA> rsa(RSA_new());
  if (!rsa) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  BN_bin2bn(public_key.data(), /*len=*/kRsa3072ModulusSize, modulus.get());
  BN_bin2bn(public_key.data() + kRsa3072ModulusSize,
            /*len=*/kRsa3072SerializedExponentSize, exponent.get());

  // Takes ownership of |modulus| and |exponent|.
  if (RSA_set0_key(rsa.get(), modulus.release(), exponent.release(),
                   /*d=*/nullptr) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(rsa);
}

StatusOr<std::vector<uint8_t>> SerializeRsa3072PublicKey(const RSA *rsa) {
  size_t rsa_size = RSA_size(rsa);
  if (rsa_size != kRsa3072ModulusSize) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Invalid public key size: ", rsa_size));
  }

  const BIGNUM *n;
  const BIGNUM *e;

  // The private exponent, d, is not set for a public key.
  RSA_get0_key(rsa, &n, &e, /*out_d=*/nullptr);

  std::vector<uint8_t> output(kRsa3072ModulusSize +
                              kRsa3072SerializedExponentSize);
  if (!BN_bn2bin_padded(output.data(), /*len=*/kRsa3072ModulusSize, n) ||
      !BN_bn2bin_padded(output.data() + kRsa3072ModulusSize,
                        /*len=*/kRsa3072SerializedExponentSize, e)) {
    return Status(absl::StatusCode::kInternal,
                  "Failed to serialize public key");
  }
  return output;
}

StatusOr<std::vector<uint8_t>> SerializePpidek(
    const AsymmetricEncryptionKeyProto &ppidek) {
  if (ppidek.key_type() != AsymmetricEncryptionKeyProto::ENCRYPTION_KEY) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "PPIDEK must be an encryption key");
  }

  AsymmetricEncryptionScheme encryption_scheme = ppidek.encryption_scheme();
  if (!AsymmetricEncryptionSchemeToPceCryptoSuite(encryption_scheme)
           .has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Unsupported encryption scheme: ",
                               ProtoEnumValueName(encryption_scheme)));
  }
  switch (encryption_scheme) {
    case AsymmetricEncryptionScheme::RSA3072_OAEP:
      return SerializeRsa3072Ppidek(ppidek);
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    absl::StrCat("Unsupported encryption scheme: ",
                                 ProtoEnumValueName(encryption_scheme)));
  }
}

StatusOr<Reportdata> CreateReportdataForGetPceInfo(
    const AsymmetricEncryptionKeyProto &ppidek) {
  std::vector<uint8_t> data_collector;
  ASYLO_ASSIGN_OR_RETURN(data_collector, SerializePpidek(ppidek));

  // This conversion is guaranteed to produce a value because |ppidek| was
  // successfully serialized.
  uint8_t crypto_suite =
      AsymmetricEncryptionSchemeToPceCryptoSuite(ppidek.encryption_scheme())
          .value();
  data_collector.insert(data_collector.begin(), crypto_suite);

  std::unique_ptr<AdditionalAuthenticatedDataGenerator> aad_generator =
      AdditionalAuthenticatedDataGenerator::CreateGetPceInfoAadGenerator();
  Reportdata reportdata;
  ASYLO_ASSIGN_OR_RETURN(reportdata.data,
                         aad_generator->Generate(data_collector));
  return reportdata;
}

}  // namespace sgx
}  // namespace asylo
