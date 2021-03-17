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
#include "absl/status/status.h"
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
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"
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

constexpr char kPckDerHex[] =
    "3077020101042058074ece9f20068fba38b3dd32febed75e9a3c54c7cd320d4d47ca45c9f2"
    "7d60a00a06082a8648ce3d030107a144034200049093de86699e3953f3cfe3107f6f8808cf"
    "82a59bd016aec0343615922fda73f8cb12018928048812d4b73b765a769d1cd6798487d3ba"
    "a861f3d8729e27050473";

constexpr char kAttestationKeyCertificateHex[] =
    "0ab3030ab00300000000000000000000000000000000010000000000000000000000000000"
    "000000000000000000000000000000000035000000000000003f0000000000000093136c09"
    "7359f6fa329a765cbfed1c47de2bcc2ea85c35c826cff2de9d3860d8000000000000000000"
    "0000000000000000000000000000000000000000000000c81210c60d3935b097b706111d57"
    "0661ccf84c95183ae2f02a25feef8c80b00f00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000023bd1205000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000013c28729d2e054"
    "0c57e401c896babbfd142a607a610c2975b8ae49f89330698f000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000e0ae182f6a886b324127d4d4c1ab5e8712dd010ac401"
    "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "4ed53c3c04981028bc33cc9dacb34e7e39115c09b20f6fd71af082978e8edd62e9a31f7000"
    "31d140ace832f33a2683464b51b5acd85654f52602f2b7d8ea8b5d1230417373657274696f"
    "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
    "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
    "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
    "12440a2044eea6fd8ac2a3776f7e5e2dfb4f20a941a6bf7096fb3eb3e4835112b39301f312"
    "208f4ed097226251debb3fb38fb3b2130daf3dbcae5702b3dfa1f34d57b9d3284d";

// The SGX identity asserted by the above certificate.
constexpr char kAttestationKeyCertAssertedIdentity[] = R"pb(
  code_identity {
    mrenclave {
      hash: "\223\023l\tsY\366\3722\232v\\\277\355\034G\336+\314.\250\\5\310&\317\362\336\2358`\330"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\310\022\020\306\r95\260\227\267\006\021\035W\006a\314\370L\225\030:\342\360*%\376\357\214\200\260\017"
      }
      isvprodid: 48419
      isvsvn: 1298
    }
    miscselect: 1
    attributes { flags: 53 xfrm: 63 }
  }
  machine_configuration {
    cpu_svn {
      value: "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
    }
  }
)pb";

constexpr char kAttestationKey[] = R"pem(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIWJb3g6rMO5aS4hzWJd3H4sLqEDHluQE07xc9asINK3oAoGCCqGSM49
AwEHoUQDQgAETtU8PASYECi8M8ydrLNOfjkRXAmyD2/XGvCCl46O3WLpox9wADHR
QKzoMvM6JoNGS1G1rNhWVPUmAvK32OqLXQ==
-----END EC PRIVATE KEY-----
)pem";

constexpr char kUserData[] = "User Data";

constexpr char kCpuSvn[] = "fedcba9876543210";

MachineConfiguration CreateMachineConfiguration() {
  MachineConfiguration machine_config;

  machine_config.mutable_cpu_svn()->set_value(kCpuSvn);
  machine_config.set_sgx_type(STANDARD);

  return machine_config;
}

StatusOr<std::unique_ptr<CertificateInterface>> CreateX509Certificate(
    const VerifyingKey &subject_key, const std::string &subject_name,
    const SigningKey &issuer_key, const std::string &issuer_name, bool is_ca,
    bool pck_cert) {
  X509CertificateBuilder builder;

  bssl::UniquePtr<BIGNUM> serial_number(BN_new());
  constexpr int kMaxNumBitsInSerialNumber = 160;
  if (BN_rand(serial_number.get(), kMaxNumBitsInSerialNumber, /*top=*/-1,
              /*bottom=*/0) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
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
  *self_identity.mutable_machine_configuration() = CreateMachineConfiguration();
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
                         EcdsaP256Sha256SigningKey::CreateFromDer(
                             absl::HexStringToBytes(kPckDerHex)));
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

  return absl::OkStatus();
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
    return Status(absl::StatusCode::kInternal, "Failed to parse AGE identity");
  }
  *age_identity.mutable_machine_configuration() = CreateMachineConfiguration();

  SgxIdentityExpectation age_sgx_expectation;
  ASYLO_ASSIGN_OR_RETURN(
      age_sgx_expectation,
      CreateSgxIdentityExpectation(age_identity,
                                   SgxIdentityMatchSpecOptions::STRICT_REMOTE));

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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
}

TEST(RemoteAssertionUtilTest, VerifyRemoteAssertionIntelChainMissingAgeCert) {
  RemoteAssertionInputs inputs;
  ASYLO_ASSERT_OK_AND_ASSIGN(inputs, GenerateRemoteAssertionInputs());

  // Reset the Intel chain to have the PCK cert assert the attestation key.
  std::unique_ptr<SigningKey> pck_signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_signing_key,
                             EcdsaP256Sha256SigningKey::CreateFromDer(
                                 absl::HexStringToBytes(kPckDerHex)));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
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
              StatusIs(absl::StatusCode::kInvalidArgument));
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
              StatusIs(absl::StatusCode::kInternal));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
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
              StatusIs(absl::StatusCode::kUnimplemented));
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
              StatusIs(absl::StatusCode::kInternal));
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
              StatusIs(absl::StatusCode::kUnauthenticated));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
