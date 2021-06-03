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

#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_generator.h"

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/internal/fake_pce.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_infrastructural_enclave_manager.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave.pb.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave_wrapper.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/init.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"

ABSL_FLAG(std::string, assertion_generator_enclave_path, "",
          "Path to the assertion generator enclave");
ABSL_FLAG(std::string, generator_test_enclave_path, "",
          "Path to the generator test enclave");

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Ge;

constexpr char kBadCertData[] = "bAD cErT";
constexpr char kBadConfig[] = "baD cOnFig";
constexpr char kBadAdditionalInfo[] = "baD inFO";

constexpr char kUserData[] = "User data";

constexpr absl::string_view kTestDerHex =
    "3082027230820217a003020102021409e3256099b2bbb1f1f60e55c7b8bf"
    "7f3dfa0e87300a06082a8648ce3d04030430818d310b3009060355040613"
    "0255533113301106035504080c0a57617368696e67746f6e3111300f0603"
    "5504070c084b69726b6c616e64310f300d060355040a0c06476f6f676c65"
    "310c300a060355040b0c03474350310f300d06035504030c066a65737369"
    "653126302406092a864886f70d01090116176a65737369652e71792e6c69"
    "7540676d61696c2e636f6d301e170d3230303932383232323430335a170d"
    "3230313032383232323430335a30818d310b300906035504061302555331"
    "13301106035504080c0a57617368696e67746f6e3111300f06035504070c"
    "084b69726b6c616e64310f300d060355040a0c06476f6f676c65310c300a"
    "060355040b0c03474350310f300d06035504030c066a6573736965312630"
    "2406092a864886f70d01090116176a65737369652e71792e6c697540676d"
    "61696c2e636f6d3059301306072a8648ce3d020106082a8648ce3d030107"
    "0342000411c4a455280b2d3c750a8df6cd80a3fbc4bdb3a3a242b98b2a13"
    "1c338f4575908e4f7be2a37d8fcaf9786bacd95ef60b39d40ef7bd1005dd"
    "2fdbc55cc3dffb8aa3533051301d0603551d0e04160414026c5a1e62738a"
    "ccd46b7d19ff7211f46b962ceb301f0603551d23041830168014026c5a1e"
    "62738accd46b7d19ff7211f46b962ceb300f0603551d130101ff04053003"
    "0101ff300a06082a8648ce3d0403040349003046022100ca8f37f452dbfa"
    "eb4e2b546e33815e186b4ca44b8f146dadca50f0534cd2fc5b022100c41c"
    "f13136b19bb4e507c9b7cb1b69f89f894737893ea5107084e2acaf33478e";

class SgxAgeRemoteAssertionGeneratorTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    ASYLO_ASSERT_OK(EnclaveManager::Configure(EnclaveManagerOptions()));
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_manager_, EnclaveManager::Instance());
    ASYLO_ASSERT_OK(InitializeAssertionGeneratorEnclave());
    ASYLO_ASSERT_OK(LoadTestEnclave());
  }

  static void TearDownTestSuite() {
    if (assertion_generator_enclave_client_) {
      ASYLO_EXPECT_OK(enclave_manager_->DestroyEnclave(
          assertion_generator_enclave_client_, EnclaveFinal(),
          /*skip_finalize=*/false));
    }
    delete test_enclave_wrapper_;
  }

  void SetUp() override {
    ASYLO_ASSERT_OK(test_enclave_wrapper_->ResetGenerator());

    SgxAgeRemoteAssertionAuthorityConfig authority_config;
    authority_config.set_server_address(*server_address_);
    *authority_config.mutable_intel_root_certificate() = *intel_root_cert_;
    for (auto certificate : *additional_root_ca_certificates_) {
      *authority_config.add_root_ca_certificates() = certificate;
    }

    ASSERT_TRUE(authority_config.SerializeToString(&config_));
  }

  // Loads the AGE, generating a key, and launching its gRPC service on a random
  // UDS address, saving it into |server_address_|.
  static Status InitializeAssertionGeneratorEnclave() {
    // Establish a random UDS address for the AGE.
    char path[] = "/tmp/SgxRemoteAssertionGeneratorEnclaveTest.XXXXXX";
    if (mkdtemp(path) == nullptr) {
      return absl::InternalError(absl::StrCat(
          "Failed to create random test directory: ", strerror(errno)));
    }
    server_address_ = new std::string(absl::StrCat("unix:", path, ".sock"));

    EnclaveLoadConfig load_config =
        SgxInfrastructuralEnclaveManager::GetAgeEnclaveLoadConfig(
            absl::GetFlag(FLAGS_assertion_generator_enclave_path),
            /*is_debuggable_enclave=*/true, *server_address_,
            GetSgxLocalAssertionAuthorityTestConfig());

    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(load_config));
    assertion_generator_enclave_client_ =
        enclave_manager_->GetClient(load_config.name());

    std::unique_ptr<sgx::FakePce> fake_pce;
    ASYLO_ASSIGN_OR_RETURN(fake_pce, sgx::FakePce::CreateFromFakePki());
    SgxInfrastructuralEnclaveManager sgx_infra_enclave_manager(
        std::move(fake_pce), assertion_generator_enclave_client_);

    // Certify the AGE with the Fake SGX PKI.
    CertificateChain certificate_chain;
    ASYLO_ASSIGN_OR_RETURN(*certificate_chain.add_certificates(),
                           sgx_infra_enclave_manager.CertifyAge());
    sgx::AppendFakePckCertificateChain(&certificate_chain);

    // Call AGE::UpdateCerts().
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    sgx::UpdateCertsInput *update_certs_input =
        enclave_input
            .MutableExtension(sgx::remote_assertion_generator_enclave_input)
            ->mutable_update_certs_input();
    *update_certs_input->add_certificate_chains() = certificate_chain;
    ASYLO_RETURN_IF_ERROR(assertion_generator_enclave_client_->EnterAndRun(
        enclave_input, &enclave_output));

    intel_root_cert_ =
        new Certificate(*certificate_chain.certificates().rbegin());
    // Save the last certificate as potential root certificate. The AGE
    // only produces assertions for the fake Intel root.
    additional_root_ca_certificates_ = new std::vector<Certificate>(
        {certificate_chain.certificates().rbegin() + 1,
         certificate_chain.certificates().rbegin() + 2});

    // Call AGE::StartServer().
    enclave_input.Clear();
    enclave_output.Clear();
    *enclave_input
         .MutableExtension(sgx::remote_assertion_generator_enclave_input)
         ->mutable_start_server_request_input() =
        sgx::StartServerRequestInput::default_instance();
    return assertion_generator_enclave_client_->EnterAndRun(enclave_input,
                                                            &enclave_output);
  }

  // Loads the SgxAgeRemoteAssertionGeneratorTestEnclave, which is used to
  // proxy calls to the SgxAgeRemoteAssertionGenerator in this test suite.
  static Status LoadTestEnclave() {
    sgx::SgxRemoteAssertionGeneratorTestEnclaveConfig enclave_config;
    SetSgxAgeRemoteAssertionDescription(enclave_config.mutable_description());

    auto wrapper = SgxRemoteAssertionGeneratorTestEnclaveWrapper::Load(
        enclave_manager_, absl::GetFlag(FLAGS_generator_test_enclave_path),
        enclave_config);
    ASYLO_RETURN_IF_ERROR(wrapper.status());
    test_enclave_wrapper_ = wrapper.value().release();

    return absl::OkStatus();
  }

  // Creates an assertion request for the SGX AGE remote assertion generator.
  StatusOr<AssertionRequest> MakeAssertionRequest(
      absl::Span<const Certificate> certificates) {
    AssertionRequest assertion_request;
    SetSgxAgeRemoteAssertionDescription(
        assertion_request.mutable_description());

    sgx::RemoteAssertionRequestAdditionalInfo additional_info;
    for (const auto &certificate : certificates) {
      *additional_info.add_root_ca_certificates() = certificate;
    }

    if (!additional_info.SerializeToString(
            assertion_request.mutable_additional_information())) {
      return Status(
          absl::StatusCode::kInvalidArgument,
          "Failed to serialize additional_info for remote assertion request");
    }

    return assertion_request;
  }

  static EnclaveManager *enclave_manager_;
  static EnclaveClient *assertion_generator_enclave_client_;
  static SgxRemoteAssertionGeneratorTestEnclaveWrapper *test_enclave_wrapper_;

  static std::string *server_address_;
  static Certificate *intel_root_cert_;
  static std::vector<Certificate> *additional_root_ca_certificates_;

  std::string config_;
};

EnclaveManager *SgxAgeRemoteAssertionGeneratorTest::enclave_manager_;
EnclaveClient
    *SgxAgeRemoteAssertionGeneratorTest::assertion_generator_enclave_client_;
SgxRemoteAssertionGeneratorTestEnclaveWrapper
    *SgxAgeRemoteAssertionGeneratorTest::test_enclave_wrapper_;
std::string *SgxAgeRemoteAssertionGeneratorTest::server_address_;
std::vector<Certificate>
    *SgxAgeRemoteAssertionGeneratorTest::additional_root_ca_certificates_;
Certificate *SgxAgeRemoteAssertionGeneratorTest::intel_root_cert_;

TEST_F(SgxAgeRemoteAssertionGeneratorTest,
       InitializeFailsWithUnparsableConfig) {
  EXPECT_THAT(test_enclave_wrapper_->Initialize(kBadConfig),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GeneratorFoundInStaticMap) {
  std::string authority_id;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      authority_id, EnclaveAssertionAuthority::GenerateAuthorityId(
                        CODE_IDENTITY, sgx::kSgxAgeRemoteAssertionAuthority));
  EXPECT_NE(AssertionGeneratorMap::GetValue(authority_id),
            AssertionGeneratorMap::value_end());
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, InitializeFailsWithNoServerAddress) {
  SgxAgeRemoteAssertionAuthorityConfig authority_config;
  *authority_config.mutable_intel_root_certificate() = *intel_root_cert_;

  std::string config;
  ASSERT_TRUE(authority_config.SerializeToString(&config));

  EXPECT_THAT(test_enclave_wrapper_->Initialize(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, InitializeFailsWithoutIntelCert) {
  SgxAgeRemoteAssertionAuthorityConfig authority_config;
  authority_config.set_server_address(*server_address_);

  std::string config;
  ASSERT_TRUE(authority_config.SerializeToString(&config));

  EXPECT_THAT(test_enclave_wrapper_->Initialize(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, InitializeFailsWithBadIntelCert) {
  Certificate certificate;
  certificate.set_format(Certificate::UNKNOWN);
  certificate.set_data(kBadCertData);

  SgxAgeRemoteAssertionAuthorityConfig authority_config;
  authority_config.set_server_address(*server_address_);
  *authority_config.mutable_intel_root_certificate() = certificate;

  std::string config;
  ASSERT_TRUE(authority_config.SerializeToString(&config));

  EXPECT_THAT(test_enclave_wrapper_->Initialize(config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, OneInitializationSingleThreaded) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));
  EXPECT_THAT(test_enclave_wrapper_->Initialize(config_),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, OneInitializationMultiThreaded) {
  constexpr int kNumThreads = 11;

  std::atomic<int> num_initializations(0);
  std::vector<Thread> threads;
  threads.reserve(kNumThreads);

  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([this, &num_initializations] {
      num_initializations +=
          test_enclave_wrapper_->Initialize(config_).ok() ? 1 : 0;
    });
  }

  for (auto &thread : threads) {
    thread.Join();
  }

  EXPECT_EQ(num_initializations.load(), 1);
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, IsInitializedState) {
  EXPECT_THAT(test_enclave_wrapper_->IsInitialized(), IsOkAndHolds(false));
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));
  EXPECT_THAT(test_enclave_wrapper_->IsInitialized(), IsOkAndHolds(true));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GenerateFailsIfNotInitialized) {
  EXPECT_THAT(test_enclave_wrapper_->IsInitialized(), IsOkAndHolds(false));
  EXPECT_THAT(
      test_enclave_wrapper_->CanGenerate(AssertionRequest::default_instance()),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CreateAssertionOfferSuccess) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  AssertionOffer assertion_offer;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_offer,
                             test_enclave_wrapper_->CreateAssertionOffer());

  const AssertionDescription &description = assertion_offer.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), sgx::kSgxAgeRemoteAssertionAuthority);

  sgx::RemoteAssertionOfferAdditionalInfo additional_info;
  ASSERT_TRUE(additional_info.ParseFromString(
      assertion_offer.additional_information()));
  EXPECT_THAT(additional_info.root_ca_certificates(),
              ElementsAre(EqualsProto(*intel_root_cert_),
                          EqualsProto((*additional_root_ca_certificates_)[0])));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CanGenerateSuccess) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  // Create a valid AssertionRequest.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      assertion_request,
      MakeAssertionRequest(
          {*intel_root_cert_, (*additional_root_ca_certificates_)[0]}));
  EXPECT_THAT(test_enclave_wrapper_->CanGenerate(assertion_request),
              IsOkAndHolds(true));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CanGenerateSuccessCertSubset) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  // Create an assertion request with only one of the two CAs contained within
  // the generator.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest({*intel_root_cert_}));

  EXPECT_THAT(test_enclave_wrapper_->CanGenerate(assertion_request),
              IsOkAndHolds(true));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CanGenerateFailureNoCerts) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request, MakeAssertionRequest({}));

  EXPECT_THAT(test_enclave_wrapper_->CanGenerate(assertion_request),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest,
       CanGenerateFailureExtraCertInRequest) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  std::vector<Certificate> certificates = *additional_root_ca_certificates_;

  // Add another valid cert into the request.
  Certificate certificate;
  certificate.set_format(Certificate::X509_DER);
  certificate.set_data(absl::HexStringToBytes(kTestDerHex));
  certificates.push_back(certificate);

  // Create a valid AssertionRequest.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest(certificates));

  EXPECT_THAT(test_enclave_wrapper_->CanGenerate(assertion_request),
              IsOkAndHolds(false));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GenerateFailureBadAssertionRequest) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  // Create an AssertionRequest with bad |additional_info|.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest({*intel_root_cert_}));
  assertion_request.set_additional_information(kBadAdditionalInfo);

  Assertion assertion;
  EXPECT_THAT(test_enclave_wrapper_->Generate(kUserData, assertion_request),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GenerateSuccess) {
  ASYLO_EXPECT_OK(test_enclave_wrapper_->Initialize(config_));

  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest({*intel_root_cert_}));

  SgxIdentity enclave_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(enclave_identity,
                             test_enclave_wrapper_->GetSgxSelfIdentity());

  // Attempt to generate an assertion 100 times to ensure that re-establishing
  // the gRPC channel to the AGE multiple times does not cause server failures.
  for (int i = 0; i < 100; ++i) {
    Assertion assertion;
    ASYLO_ASSERT_OK_AND_ASSIGN(assertion, test_enclave_wrapper_->Generate(
                                              kUserData, assertion_request));

    const AssertionDescription &description = assertion.description();
    EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
    EXPECT_EQ(description.authority_type(),
              sgx::kSgxAgeRemoteAssertionAuthority);

    sgx::RemoteAssertion remote_assertion;
    ASSERT_TRUE(remote_assertion.ParseFromString(assertion.assertion()));

    ASSERT_THAT(remote_assertion.certificate_chains().size(), Eq(1));
    CertificateChain certificate_chain = remote_assertion.certificate_chains(0);

    ASSERT_THAT(certificate_chain.certificates().size(), Ge(1));

    const Certificate &root_cert = *certificate_chain.certificates().rbegin();
    EXPECT_THAT(root_cert, EqualsProto(*intel_root_cert_));

    sgx::RemoteAssertionPayload payload;
    ASSERT_TRUE(payload.ParseFromString(remote_assertion.payload()));

    EXPECT_THAT(payload.identity(), EqualsProto(enclave_identity));
    EXPECT_EQ(payload.user_data(), kUserData);
  }
}

}  // namespace
}  // namespace asylo
