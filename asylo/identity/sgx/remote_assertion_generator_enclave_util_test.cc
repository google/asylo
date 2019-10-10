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

#include "asylo/identity/sgx/remote_assertion_generator_enclave_util.h"

#include <cstdint>
#include <memory>
#include <vector>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sealed_secret.pb.h"
#include "asylo/identity/sgx/attestation_key.pb.h"
#include "asylo/identity/sgx/remote_assertion_generator_constants.h"
#include "asylo/identity/sgx/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/sgx/sgx_local_secret_sealer.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::SizeIs;

constexpr char kIncorrectSecretName[] =
    "Incorrect Assertion Generator Enclave Secret";
constexpr char kIncorrectSecretVersion[] =
    "Incorrect Assertion Generator Enclave Secret v1";
constexpr char kIncorrectSecretPurpose[] =
    "Incorrect Assertion Generator Enclave Attestation Key and Certificates";
constexpr char kIncorrectAad[] = "Incorrect Aad";
constexpr char kIncorrectSealedSecret[] = "Incorrect Enclave Secret";
constexpr char kCertificateChain[] = R"proto(
  certificates: { format: X509_DER data: "child" }
  certificates: { format: X509_DER data: "root" }
)proto";
constexpr char kTestVerifyingKeyDer[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004eaeda5103e89194f43bf"
    "e0d844f3e79f000957fc3c9237c7ea8ddcd67e22c75cd75119ea9aa02f76cecacbbf1b2fe6"
    "1c69fc9eeada1fe29a567d6ceb468e16bd";
constexpr char kReportdata[] =
    "9c8e7ba2fbeef50173645c125a9ac25088894d4cdb41502506cfaa6ccd7771490000000000"
    "00000000000000000000004153594c4f205349474e5245504f5254";

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestRemoteAssertionGeneratorEnclaveHeaderSuccess) {
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  EXPECT_THAT(CheckRemoteAssertionGeneratorEnclaveSecretHeader(header), IsOk());
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestRemoteAssertionGeneratorEnclaveHeaderIncorrectName) {
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  header.set_secret_name(kIncorrectSecretName);
  EXPECT_THAT(CheckRemoteAssertionGeneratorEnclaveSecretHeader(header),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "Invalid sealed secret header: incorrect secret name"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestRemoteAssertionGeneratorEnclaveHeaderIncorrectVersion) {
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  header.set_secret_version(kIncorrectSecretVersion);
  EXPECT_THAT(
      CheckRemoteAssertionGeneratorEnclaveSecretHeader(header),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               "Invalid sealed secret header: incorrect secret version"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestRemoteAssertionGeneratorEnclaveHeaderIncorrectPurpose) {
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  header.set_secret_purpose(kIncorrectSecretPurpose);
  EXPECT_THAT(
      CheckRemoteAssertionGeneratorEnclaveSecretHeader(header),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               "Invalid sealed secret header: incorrect secret purpose"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestExtractAttestationKeySuccess) {
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  AsymmetricSigningKeyProto asymmetric_signing_key_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      asymmetric_signing_key_proto,
      GetAsymmetricSigningKeyProtoFromSigningKey(*attestation_key));

  std::unique_ptr<SigningKey> attestation_key_extracted;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key_extracted,
                             ExtractAttestationKeyFromAsymmetricSigningKeyProto(
                                 asymmetric_signing_key_proto));

  CleansingVector<uint8_t> serialized_key_expected;
  ASYLO_ASSERT_OK(attestation_key->SerializeToDer(&serialized_key_expected));
  CleansingVector<uint8_t> serialized_key_actual;
  ASYLO_ASSERT_OK(
      attestation_key_extracted->SerializeToDer(&serialized_key_actual));
  EXPECT_THAT(serialized_key_actual, Eq(serialized_key_expected));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestExtractAttestationKeyThatHasIncorrectKeyTypeFails) {
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  AsymmetricSigningKeyProto asymmetric_signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      asymmetric_signing_key,
      GetAsymmetricSigningKeyProtoFromSigningKey(*attestation_key));

  // Set key type to invalid type.
  asymmetric_signing_key.set_key_type(AsymmetricSigningKeyProto::VERIFYING_KEY);

  EXPECT_THAT(
      ExtractAttestationKeyFromAsymmetricSigningKeyProto(
          asymmetric_signing_key),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               absl::StrCat("The sealed secret key has invalid key type: ",
                            AsymmetricSigningKeyProto_KeyType_Name(
                                asymmetric_signing_key.key_type()))));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestExtractAttestationKeyThatHasIncorrectEncodingFails) {
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  AsymmetricSigningKeyProto asymmetric_signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      asymmetric_signing_key,
      GetAsymmetricSigningKeyProtoFromSigningKey(*attestation_key));

  // Set key type to invalid encoding.
  asymmetric_signing_key.set_encoding(
      AsymmetricKeyEncoding::ASYMMETRIC_KEY_PEM);

  EXPECT_THAT(
      ExtractAttestationKeyFromAsymmetricSigningKeyProto(
          asymmetric_signing_key),
      StatusIs(
          error::GoogleError::UNIMPLEMENTED,
          "Create attestation key from a PEM-encoded key is not supported"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestExtractAttestationKeyAndCertsThatHasIncorretSecretHeaderFails) {
  SealedSecretHeader invalid_header =
      GetRemoteAssertionGeneratorEnclaveSecretHeader();
  invalid_header.set_secret_purpose(kIncorrectSecretPurpose);
  UpdateCertsInput update_certs_input;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kCertificateChain, update_certs_input.add_certificate_chains()));
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  SealedSecret sealed_secret;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      sealed_secret, CreateSealedSecret(invalid_header,
                                        update_certs_input.certificate_chains(),
                                        *attestation_key));

  std::vector<CertificateChain> certificate_chains_extracted;
  EXPECT_THAT(
      ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
          sealed_secret, &certificate_chains_extracted),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               "Invalid sealed secret header: incorrect secret purpose"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestExtractAttestationKeyAndCertsThatHasInvalidAadFails) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  sealer->SetDefaultHeader(&header);
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  RemoteAssertionGeneratorEnclaveSecret enclave_secret;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *enclave_secret.mutable_attestation_key(),
      GetAsymmetricSigningKeyProtoFromSigningKey(*attestation_key));

  SealedSecret sealed_secret;
  sealer->Seal(header, {kIncorrectAad}, {enclave_secret.SerializeAsString()},
               &sealed_secret);

  std::vector<CertificateChain> certificate_chains_extracted;
  EXPECT_THAT(ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
                  sealed_secret, &certificate_chains_extracted),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "Cannot parse the additional authenticated data"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestExtractAttestationKeyAndCertsThatHasIncorrectSealedSecretFails) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  sealer->SetDefaultHeader(&header);
  RemoteAssertionGeneratorEnclaveSecret enclave_secret;
  RemoteAssertionGeneratorEnclaveSecretAad aad;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kCertificateChain, aad.add_certificate_chains()));
  SealedSecret sealed_secret;
  sealer->Seal(header, {aad.SerializeAsString()}, {kIncorrectSealedSecret},
               &sealed_secret);

  std::vector<CertificateChain> certificate_chains_extracted;
  EXPECT_THAT(ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
                  sealed_secret, &certificate_chains_extracted),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "Cannot parse the sealed secret"));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestCreateAndExtractSecretSuccess) {
  // Create sealed secret.
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  UpdateCertsInput update_certs_input;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kCertificateChain, update_certs_input.add_certificate_chains()));
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  SealedSecret sealed_secret;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      sealed_secret,
      CreateSealedSecret(header, update_certs_input.certificate_chains(),
                         *attestation_key));

  // Unseal to get attestation key and certificate chains.
  std::unique_ptr<SigningKey> unsealed_attestation_key;
  std::vector<CertificateChain> unsealed_certificate_chains;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      unsealed_attestation_key,
      ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
          sealed_secret, &unsealed_certificate_chains));

  // Verify attestation key and certificates.
  EXPECT_THAT(unsealed_certificate_chains, SizeIs(1));
  EXPECT_THAT(unsealed_certificate_chains[0],
              EqualsProto(update_certs_input.certificate_chains(0)));
  CleansingVector<uint8_t> serialized_key_expected;
  CleansingVector<uint8_t> serialized_key_actual;
  ASYLO_ASSERT_OK(attestation_key->SerializeToDer(&serialized_key_expected));
  ASYLO_ASSERT_OK(
      unsealed_attestation_key->SerializeToDer(&serialized_key_actual));
  EXPECT_THAT(serialized_key_actual, Eq(serialized_key_expected));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestGetAsymmetricSigningKeyProtoForSigningKeySuccess) {
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());

  AsymmetricSigningKeyProto asymmetric_signing_key_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      asymmetric_signing_key_proto,
      GetAsymmetricSigningKeyProtoFromSigningKey(*attestation_key));

  EXPECT_THAT(asymmetric_signing_key_proto.key_type(),
              Eq(AsymmetricSigningKeyProto::SIGNING_KEY));
  EXPECT_THAT(asymmetric_signing_key_proto.encoding(),
              Eq(AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER));
  EXPECT_THAT(asymmetric_signing_key_proto.signature_scheme(),
              Eq(attestation_key->GetSignatureScheme()));

  CleansingVector<uint8_t> serialized_attestation_key;
  ASYLO_ASSERT_OK(attestation_key->SerializeToDer(&serialized_attestation_key));
  std::string key_expected = {serialized_attestation_key.begin(),
                              serialized_attestation_key.end()};
  EXPECT_THAT(asymmetric_signing_key_proto.key(), Eq(key_expected));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestGetSerializedPceSignReportPayloadFromVerifyingKeySuccess) {
  std::unique_ptr<SigningKey> attestation_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_key,
                             EcdsaP256Sha256SigningKey::Create());
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key, attestation_key->GetVerifyingKey());

  std::string serialized_pce_sign_report_payload;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      serialized_pce_sign_report_payload,
      CreateSerializedPceSignReportPayloadFromVerifyingKey(*verifying_key));
  PceSignReportPayload pce_sign_report_payload;
  pce_sign_report_payload.ParseFromString(serialized_pce_sign_report_payload);

  EXPECT_THAT(pce_sign_report_payload.version(),
              Eq(kPceSignReportPayloadVersion));

  const AttestationPublicKey &public_key =
      pce_sign_report_payload.attestation_public_key();
  EXPECT_THAT(public_key.purpose(), Eq(kAttestationPublicKeyPurpose));
  EXPECT_THAT(public_key.version(), Eq(kAttestationPublicKeyVersion));

  AsymmetricSigningKeyProto asymmetric_signing_key_proto =
      public_key.attestation_public_key();

  EXPECT_THAT(asymmetric_signing_key_proto.key_type(),
              Eq(AsymmetricSigningKeyProto::VERIFYING_KEY));
  EXPECT_THAT(asymmetric_signing_key_proto.encoding(),
              Eq(AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER));
  EXPECT_THAT(asymmetric_signing_key_proto.signature_scheme(),
              Eq(verifying_key->GetSignatureScheme()));

  std::string serialized_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(serialized_key, verifying_key->SerializeToDer());
  EXPECT_THAT(asymmetric_signing_key_proto.key(), Eq(serialized_key));
}

TEST(RemoteAssertionGeneratorEnclaveUtilTest,
     TestGenerateReportdataOnAttestationPublicKeySuccess) {
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key,
                             EcdsaP256Sha256VerifyingKey::CreateFromDer(
                                 absl::HexStringToBytes(kTestVerifyingKeyDer)));
  std::string serialized_pce_sign_report_payload;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      serialized_pce_sign_report_payload,
      CreateSerializedPceSignReportPayloadFromVerifyingKey(*verifying_key));

  Reportdata actual_reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(actual_reportdata,
                             GenerateReportdataForPceSignReportProtocol(
                                 serialized_pce_sign_report_payload));
  Reportdata expected_reportdata;
  ASYLO_ASSERT_OK(
      SetTrivialObjectFromHexString(kReportdata, &expected_reportdata.data));
  EXPECT_THAT(actual_reportdata.data, Eq(expected_reportdata.data));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
