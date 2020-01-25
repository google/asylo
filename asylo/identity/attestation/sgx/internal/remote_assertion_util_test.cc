/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"

#include <openssl/base.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/fake_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/sgx/pck_certificate_util.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

struct RemoteAssertionInputs {
  std::vector<CertificateChain> certificate_chains;
  CertificateInterfaceVector required_roots;
  SgxIdentity self_identity;
  std::unique_ptr<SigningKey> attestation_signing_key;
  std::unique_ptr<CertificateInterface> intel_root;
  IdentityAclPredicate age_expectation;
};

constexpr char kPckPem[] =
    R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFgHTs6fIAaPujiz3TL+vtdemjxUx80yDU1HykXJ8n1goAoGCCqGSM49
AwEHoUQDQgAEkJPehmmeOVPzz+MQf2+ICM+CpZvQFq7ANDYVki/ac/jLEgGJKASI
EtS3O3Zadp0c1nmEh9O6qGHz2HKeJwUEcw==
-----END EC PRIVATE KEY-----)";

constexpr char kAttestationKeyCertificateHex[] =
    "0ab3030ab00300000000000000000000000000000000010000000000000000000000000000"
    "000000000000000000000000000000000027000000000000002700000000000000b0f58825"
    "c26d5277c20aaaef3b3493aafcef70f36957b3d90712ee2c96b3f652000000000000000000"
    "0000000000000000000000000000000000000000000000bdf1e39990510cf9429fae5fa64b"
    "6cd39a67c99958a0103ba9be7948aae7de0c00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000001e2c389c000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000164dc4494a164c"
    "30afafb33f4bbbef77506c65b1d48fe4a47729594a86e2affa000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000e2543dbcb2c76a13001e0a9aa072526912dd010ac401"
    "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "bb69f2e901d926d9d7e7469d690176f904148b96887e890e5bb1b21c6018c85333f65500ca"
    "2699d4702ec98986cc0c10a0ff13ae37517aae3926328c3f0b82681230417373657274696f"
    "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
    "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
    "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
    "12440a20a6a6e3bf578aa7bb236bae4cf90eb2d69ce703c35354c860826f8a8d424d9b7d12"
    "20b375ee4ba12e616889ebb0ad47489c73c7977fa053c40476c2ee9852f1279d51";

// The SGX identity asserted by the above certificate.
constexpr char kAttestationKeyCertAssertedIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\xb0\xf5\x88\x25\xc2\x6d\x52\x77\xc2\x0a\xaa\xef\x3b\x34\x93\xaa\xfc\xef\x70\xf3\x69\x57\xb3\xd9\x07\x12\xee\x2c\x96\xb3\xf6\x52"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\xbd\xf1\xe3\x99\x90\x51\x0c\xf9\x42\x9f\xae\x5f\xa6\x4b\x6c\xd3\x9a\x67\xc9\x99\x58\xa0\x10\x3b\xa9\xbe\x79\x48\xaa\xe7\xde\x0c"
      }
      isvprodid: 11294
      isvsvn: 39992
    }
    miscselect: 1
    attributes { flags: 39 xfrm: 39 }
  }
  machine_configuration {
    cpu_svn {
      value: "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    }
  }
)pb";

constexpr char kAttestationKey[] =
    R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIvKT5v6dQMDZsbNjWtnUxTGxJPHQYaAzboLcKWOopxroAoGCCqGSM49
AwEHoUQDQgAEu2ny6QHZJtnX50adaQF2+QQUi5aIfokOW7GyHGAYyFMz9lUAyiaZ
1HAuyYmGzAwQoP8TrjdReq45JjKMPwuCaA==
-----END EC PRIVATE KEY-----)";

constexpr char kUserData[] = "User Data";

constexpr char kCpuSvn[] = "fedcba9876543210";

StatusOr<std::unique_ptr<CertificateInterface>> CreateX509Certificate(
    const VerifyingKey &subject_key, const std::string &subject_name,
    const SigningKey &issuer_key, const std::string &issuer_name, bool is_ca,
    bool pck_cert) {
  X509CertificateBuilder builder;

  bssl::UniquePtr<BIGNUM> serial_number(BN_new());
  constexpr int kMaxNumBitsInSerialNumber = 160;
  if (BN_rand(serial_number.get(), kMaxNumBitsInSerialNumber, /*top=*/-1,
              /*bottom=*/0) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  builder.serial_number = std::move(serial_number);

  X509NameEntry issuer_name_entry;
  ASYLO_ASSIGN_OR_RETURN(issuer_name_entry.field,
                         ObjectId::CreateFromShortName("CN"));
  issuer_name_entry.value = issuer_name;
  builder.issuer = {issuer_name_entry};

  builder.validity = {absl::Now() - absl::Hours(10000),
                      absl::Now() + absl::Hours(10000)};

  X509NameEntry subject_name_entry;
  ASYLO_ASSIGN_OR_RETURN(subject_name_entry.field,
                         ObjectId::CreateFromShortName("CN"));
  subject_name_entry.value = subject_name;
  builder.subject = {subject_name_entry};

  BasicConstraints basic_constraints;
  basic_constraints.is_ca = is_ca;
  builder.basic_constraints = basic_constraints;

  ASYLO_ASSIGN_OR_RETURN(builder.subject_public_key_der,
                         subject_key.SerializeToDer());

  if (pck_cert) {
    SgxExtensions extensions;
    extensions.ppid.set_value("PPIDPPIDPPIDPPID");
    extensions.tcb.set_components("0123456789abcdef");
    extensions.tcb.mutable_pce_svn()->set_value(7);
    extensions.cpu_svn.set_value(kCpuSvn);
    extensions.pce_id.set_value(1);
    extensions.fmspc.set_value("FMSPC!");
    extensions.sgx_type = SgxType::STANDARD;
    X509Extension x509_extension;
    x509_extension.oid = GetSgxExtensionsOid();
    ASYLO_ASSIGN_OR_RETURN(x509_extension.value,
                           WriteSgxExtensions(extensions));
    builder.other_extensions = {x509_extension};
  }

  std::unique_ptr<X509Certificate> x509_certificate;
  return builder.SignAndBuild(issuer_key);
}

StatusOr<Certificate> CreateX509CertProto(const VerifyingKey &subject_key,
                                          const std::string &subject_name,
                                          const SigningKey &issuer_key,
                                          const std::string &issuer_name,
                                          bool is_ca, bool pck_cert = false) {
  std::unique_ptr<CertificateInterface> x509_cert;
  ASYLO_ASSIGN_OR_RETURN(
      x509_cert, CreateX509Certificate(subject_key, subject_name, issuer_key,
                                       issuer_name, is_ca, pck_cert));
  return x509_cert->ToCertificateProto(Certificate::X509_PEM);
}

Certificate Cert(Certificate::CertificateFormat format,
                 const std::string &data) {
  Certificate root_cert;
  root_cert.set_format(format);
  root_cert.set_data(data);
  return root_cert;
}

SgxIdentity GetSelfRemoteIdentity() {
  SgxIdentity self_identity = GetSelfSgxIdentity();
  MachineConfiguration *machine_config =
      self_identity.mutable_machine_configuration();
  machine_config->mutable_cpu_svn()->set_value(kCpuSvn);
  machine_config->set_sgx_type(STANDARD);
  return self_identity;
}

Status GenerateIntelChain(bool include_pck_cert, CertificateChain *intel_chain,
                          std::unique_ptr<CertificateInterface> *intel_root) {
  intel_chain->clear_certificates();

  *intel_chain->add_certificates() =
      Cert(Certificate::SGX_ATTESTATION_KEY_CERTIFICATE,
           absl::HexStringToBytes(kAttestationKeyCertificateHex));
  std::unique_ptr<SigningKey> pck_signing_key;
  ASYLO_ASSIGN_OR_RETURN(pck_signing_key,
                         EcdsaP256Sha256SigningKey::CreateFromPem(kPckPem));
  std::unique_ptr<VerifyingKey> pck_verifying_key;
  ASYLO_ASSIGN_OR_RETURN(pck_verifying_key, pck_signing_key->GetVerifyingKey());
  std::unique_ptr<SigningKey> intermediate_signing_key;
  ASYLO_ASSIGN_OR_RETURN(intermediate_signing_key,
                         EcdsaP256Sha256SigningKey::Create());
  ASYLO_ASSIGN_OR_RETURN(
      *intel_chain->add_certificates(),
      CreateX509CertProto(*pck_verifying_key, "PCK cert",
                          *intermediate_signing_key, "Intel processor cert",
                          /*is_ca=*/false, include_pck_cert));

  std::unique_ptr<VerifyingKey> intermediate_verifying_key;
  ASYLO_ASSIGN_OR_RETURN(intermediate_verifying_key,
                         intermediate_signing_key->GetVerifyingKey());
  std::unique_ptr<SigningKey> intel_root_signing_key;
  ASYLO_ASSIGN_OR_RETURN(intel_root_signing_key,
                         EcdsaP256Sha256SigningKey::Create());
  ASYLO_ASSIGN_OR_RETURN(
      *intel_chain->add_certificates(),
      CreateX509CertProto(*intermediate_verifying_key, "Intel processor cert",
                          *intel_root_signing_key, "Intel root CA",
                          /*is_ca=*/true));

  std::unique_ptr<VerifyingKey> intel_root_verifying_key;
  ASYLO_ASSIGN_OR_RETURN(intel_root_verifying_key,
                         intel_root_signing_key->GetVerifyingKey());

  ASYLO_ASSIGN_OR_RETURN(
      *intel_root,
      CreateX509Certificate(*intel_root_verifying_key, "Intel root CA",
                            *intel_root_signing_key, "Intel root CA",
                            /*is_ca=*/true, /*pck_cert=*/false));

  ASYLO_ASSIGN_OR_RETURN(
      *intel_chain->add_certificates(),
      intel_root->get()->ToCertificateProto(Certificate::X509_PEM));

  return Status::OkStatus();
}

StatusOr<RemoteAssertionInputs> GenerateRemoteAssertionInputs() {
  RemoteAssertionInputs inputs;
  CertificateChain intel_chain;
  ASYLO_RETURN_IF_ERROR(GenerateIntelChain(
      /*include_pck_cert=*/true, &intel_chain, &inputs.intel_root));

  CertificateChain required_chain;

  ASYLO_ASSIGN_OR_RETURN(
      inputs.attestation_signing_key,
      EcdsaP256Sha256SigningKey::CreateFromPem(kAttestationKey));

  std::unique_ptr<VerifyingKey> attestation_verifying_key;
  ASYLO_ASSIGN_OR_RETURN(attestation_verifying_key,
                         inputs.attestation_signing_key->GetVerifyingKey());
  std::unique_ptr<SigningKey> required_root_signing_key;
  ASYLO_ASSIGN_OR_RETURN(required_root_signing_key,
                         EcdsaP256Sha256SigningKey::Create());
  ASYLO_ASSIGN_OR_RETURN(
      *required_chain.add_certificates(),
      CreateX509CertProto(*attestation_verifying_key, "Other user cert",
                          *required_root_signing_key, "Required root CA",
                          /*is_ca=*/false));

  std::unique_ptr<VerifyingKey> required_root_verifying_key;
  ASYLO_ASSIGN_OR_RETURN(required_root_verifying_key,
                         required_root_signing_key->GetVerifyingKey());

  std::unique_ptr<CertificateInterface> required_root;
  ASYLO_ASSIGN_OR_RETURN(
      required_root,
      CreateX509Certificate(*required_root_verifying_key, "Required root CA",
                            *required_root_signing_key, "Required root CA",
                            /*is_ca=*/true, /*pck_cert=*/false));
  ASYLO_ASSIGN_OR_RETURN(
      *required_chain.add_certificates(),
      required_root->ToCertificateProto(Certificate::X509_DER));

  inputs.certificate_chains.push_back(intel_chain);
  inputs.certificate_chains.push_back(required_chain);

  inputs.required_roots.push_back(std::move(required_root));

  inputs.self_identity = GetSelfRemoteIdentity();

  SgxIdentity age_identity;
  if (!google::protobuf::TextFormat::ParseFromString(kAttestationKeyCertAssertedIdentity,
                                           &age_identity)) {
    return Status(error::GoogleError::INTERNAL, "Failed to parse AGE identity");
  }

  SgxIdentityExpectation age_sgx_expectation;
  ASYLO_ASSIGN_OR_RETURN(
      age_sgx_expectation,
      CreateSgxIdentityExpectation(age_identity,
                                   SgxIdentityMatchSpecOptions::STRICT_LOCAL));

  ASYLO_ASSIGN_OR_RETURN(*inputs.age_expectation.mutable_expectation(),
                         SerializeSgxIdentityExpectation(age_sgx_expectation));
  return std::move(inputs);
}

TEST(RemoteAssertionUtilTest, MakeRemoteAssertionSucceeds) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());
  RemoteAssertion assertion;
  ASSERT_THAT(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                  *inputs.attestation_signing_key,
                                  inputs.certificate_chains, &assertion),
              IsOk());

  std::unique_ptr<VerifyingKey> actual_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      actual_verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromProto(assertion.verifying_key()));

  std::unique_ptr<VerifyingKey> attestation_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_verifying_key,
                             inputs.attestation_signing_key->GetVerifyingKey());
  EXPECT_EQ(*actual_verifying_key, *attestation_verifying_key);

  EXPECT_EQ(assertion.certificate_chains_size(),
            inputs.certificate_chains.size());

  RemoteAssertionPayload payload;
  ASSERT_TRUE(payload.ParseFromString(assertion.payload()));
  EXPECT_EQ(payload.signature_scheme(),
            inputs.attestation_signing_key->GetSignatureScheme());
  EXPECT_EQ(payload.user_data(), kUserData);
  EXPECT_THAT(payload.identity(), EqualsProto(inputs.self_identity));

  ASYLO_EXPECT_OK(
      actual_verifying_key->Verify(assertion.payload(), assertion.signature()));
}

TEST(RemoteAssertionUtilTest, MakeAndVerifyRemoteAssertionSucceeds) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  ASYLO_ASSERT_OK(VerifyRemoteAssertion(
      kUserData, assertion, *inputs.intel_root, inputs.required_roots,
      inputs.age_expectation, &actual_identity));
  EXPECT_THAT(actual_identity, EqualsProto(inputs.self_identity));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionMissingRequiredChain) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());
  inputs.certificate_chains
      .pop_back();  // Erase the chain for the required root.

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(RemoteAssertionUtilTest,
     VerifyRemoteAssertionRequiredChainDifferentSubjectKey) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  inputs.certificate_chains[1].mutable_certificates()->erase(
      inputs.certificate_chains[1].mutable_certificates()->begin());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionMissingIntelChain) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());
  inputs.certificate_chains.erase(
      inputs.certificate_chains.begin());  // Erase the Intel chain.

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(RemoteAssertionUtilTest,
     VerifyRemoteAssertionIntelChainDifferentSubjectKey) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());
  inputs.required_roots.clear();  // Remove required root chain.

  // Set signing key to be different from one attested by Intel chain.
  std::unique_ptr<SigningKey> different_signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(different_signing_key,
                             EcdsaP256Sha256SigningKey::Create());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *different_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionIntelChainMissingAgeCert) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  // Reset the Intel chain to have the PCK cert assert the attestation key.
  std::unique_ptr<SigningKey> pck_signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_signing_key,
                             EcdsaP256Sha256SigningKey::CreateFromPem(kPckPem));
  std::unique_ptr<VerifyingKey> attestation_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(attestation_verifying_key,
                             inputs.attestation_signing_key->GetVerifyingKey());
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *inputs.certificate_chains[0].mutable_certificates(0),
      CreateX509CertProto(*attestation_verifying_key,
                          /*subject_name=*/"AK Cert", *pck_signing_key,
                          /*issuer_name=*/"PCK Cert", /*is_ca=*/false));

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionIntelChainMissingPckCert) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  // Reset the Intel chain to have the intermediate cert assert the PCK.
  ASSERT_NO_FATAL_FAILURE(GenerateIntelChain(/*include_pck_cert=*/false,
                                             &inputs.certificate_chains[0],
                                             &inputs.intel_root));

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionInvalidSignature) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));
  assertion.set_signature("a");

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionMismatchedUserData) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion("Different user data", assertion,
                                    *inputs.intel_root, inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionMismatchedSignatureScheme) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));
  assertion.mutable_verifying_key()->set_signature_scheme(
      UNKNOWN_SIGNATURE_SCHEME);

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionUnknownSignatureScheme) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  RemoteAssertion assertion;
  FakeSigningKey signing_key(UNKNOWN_SIGNATURE_SCHEME, kAttestationKey);
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      signing_key, inputs.certificate_chains,
                                      &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionInvalidCertificateChain) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());
  inputs.certificate_chains[0].mutable_certificates()->SwapElements(1, 2);

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionInvalidAgeIdentity) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  RemoteAssertion assertion;
  ASYLO_ASSERT_OK(MakeRemoteAssertion(kUserData, inputs.self_identity,
                                      *inputs.attestation_signing_key,
                                      inputs.certificate_chains, &assertion));

  SgxIdentity age_modified_sgx_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      age_modified_sgx_identity,
      ParseSgxIdentity(
          inputs.age_expectation.expectation().reference_identity()));

  age_modified_sgx_identity.mutable_code_identity()
      ->mutable_mrenclave()
      ->mutable_hash()
      ->back() ^= 1;

  ASYLO_ASSERT_OK_AND_ASSIGN(*inputs.age_expectation.mutable_expectation()
                                  ->mutable_reference_identity(),
                             SerializeSgxIdentity(age_modified_sgx_identity));

  SgxIdentity actual_identity;
  EXPECT_THAT(VerifyRemoteAssertion(kUserData, assertion, *inputs.intel_root,
                                    inputs.required_roots,
                                    inputs.age_expectation, &actual_identity),
              StatusIs(error::GoogleError::UNAUTHENTICATED));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
