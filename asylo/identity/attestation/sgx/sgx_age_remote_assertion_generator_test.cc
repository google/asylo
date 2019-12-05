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
#include <string>

#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_authority_config.pb.h"
#include "asylo/identity/attestation/sgx/sgx_age_remote_assertion_generator_test_enclave.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/init.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/sgx/sgx_identity.pb.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
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

constexpr char kAgeName[] = "AGE";
constexpr char kTestEnclaveName[] = "Test Generator Enclave";

constexpr char kBadCertData[] = "bAD cErT";
constexpr char kBadConfig[] = "baD cOnFig";
constexpr char kBadAdditionalInfo[] = "baD inFO";

constexpr char kRootCertificate1[] = R"pb(
  format: X509_DER data: "CA 1"
)pb";
constexpr char kRootCertificate2[] = R"pb(
  format: X509_DER data: "CA 2"
)pb";

constexpr char kUserData[] = "User data";

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
    if (test_enclave_client_) {
      ASYLO_EXPECT_OK(
          enclave_manager_->DestroyEnclave(test_enclave_client_, EnclaveFinal(),
                                           /*skip_finalize=*/false));
    }
  }

  void SetUp() override {
    EnclaveResetGenerator();

    SgxAgeRemoteAssertionAuthorityConfig authority_config;
    authority_config.set_server_address(*server_address_);
    for (auto certificate : *root_ca_certificates_) {
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
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat("Failed to create random test directory: ",
                                 strerror(errno)));
    }
    server_address_ = new std::string(absl::StrCat("unix:", path, ".sock"));

    // Add assertion authority and server address to the AGE config.
    assertion_generator_enclave_config_ = new EnclaveConfig();
    *assertion_generator_enclave_config_
         ->add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();
    assertion_generator_enclave_config_
        ->MutableExtension(sgx::remote_assertion_generator_enclave_config)
        ->set_remote_assertion_generator_server_address(*server_address_);

    // Load in potential certificates.
    Certificate root_certificate_1;
    google::protobuf::TextFormat::ParseFromString(kRootCertificate1, &root_certificate_1);
    Certificate root_certificate_2;
    google::protobuf::TextFormat::ParseFromString(kRootCertificate2, &root_certificate_2);
    root_ca_certificates_ =
        new std::vector<Certificate>({root_certificate_1, root_certificate_2});

    // Create an EnclaveLoadConfig object.
    EnclaveLoadConfig load_config;
    load_config.set_name(kAgeName);
    *load_config.mutable_config() = *assertion_generator_enclave_config_;

    // Create an SgxLoadConfig object.
    SgxLoadConfig sgx_config;
    SgxLoadConfig::FileEnclaveConfig file_enclave_config;
    file_enclave_config.set_enclave_path(
        absl::GetFlag(FLAGS_assertion_generator_enclave_path));
    *sgx_config.mutable_file_enclave_config() = file_enclave_config;
    sgx_config.set_debug(true);

    // Set an SGX message extension to load_config.
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(load_config));
    assertion_generator_enclave_client_ = enclave_manager_->GetClient(kAgeName);

    // Call AGE::GenerateKeyAndCsr().
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    *enclave_input
         .MutableExtension(sgx::remote_assertion_generator_enclave_input)
         ->mutable_generate_key_and_csr_input() =
        sgx::GenerateKeyAndCsrInput::default_instance();
    ASYLO_RETURN_IF_ERROR(assertion_generator_enclave_client_->EnterAndRun(
        enclave_input, &enclave_output));

    // Call AGE::UpdateCerts().
    enclave_input.Clear();
    CertificateChain chain_1;
    *chain_1.add_certificates() = root_certificate_1;
    CertificateChain chain_2;
    *chain_1.add_certificates() = root_certificate_2;
    *enclave_input
         .MutableExtension(sgx::remote_assertion_generator_enclave_input)
         ->mutable_update_certs_input()
         ->add_certificate_chains() = chain_1;
    *enclave_input
         .MutableExtension(sgx::remote_assertion_generator_enclave_input)
         ->mutable_update_certs_input()
         ->add_certificate_chains() = chain_2;
    ASYLO_RETURN_IF_ERROR(assertion_generator_enclave_client_->EnterAndRun(
        enclave_input, &enclave_output));

    // Call AGE::StartServer().
    enclave_input.Clear();
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
    test_enclave_config_ = new EnclaveConfig;
    *test_enclave_config_->add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();

    // Create an EnclaveLoadConfig object.
    EnclaveLoadConfig load_config;
    load_config.set_name(kTestEnclaveName);
    *load_config.mutable_config() = *test_enclave_config_;

    // Create an SgxLoadConfig object.
    SgxLoadConfig sgx_config;
    SgxLoadConfig::FileEnclaveConfig file_enclave_config;
    file_enclave_config.set_enclave_path(
        absl::GetFlag(FLAGS_generator_test_enclave_path));
    *sgx_config.mutable_file_enclave_config() = file_enclave_config;
    sgx_config.set_debug(true);

    // Set an SGX message extension to load_config.
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(load_config));
    test_enclave_client_ = enclave_manager_->GetClient(kTestEnclaveName);

    return Status::OkStatus();
  }

  // Creates an assertion request for the SGX AGE remote assertion generator.
  StatusOr<AssertionRequest> MakeAssertionRequest(
      std::vector<Certificate> *certificates = root_ca_certificates_) {
    AssertionRequest assertion_request;
    SetSgxAgeRemoteAssertionDescription(
        assertion_request.mutable_description());

    sgx::RemoteAssertionRequestAdditionalInfo additional_info;
    for (const auto &certificate : *certificates) {
      *additional_info.add_root_ca_certificates() = certificate;
    }

    if (!additional_info.SerializeToString(
            assertion_request.mutable_additional_information())) {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "Failed to serialize additional_info for remote assertion request");
    }

    return assertion_request;
  }

  // Returns the self identity of the test enclave.
  StatusOr<SgxIdentity> EnclaveSgxSelfIdentity() {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    *enclave_input
         .MutableExtension(
             sgx::sgx_age_remote_assertion_generator_test_enclave_input)
         ->mutable_sgx_self_identity_input() = sgx::SgxSelfIdentityInput();

    ASYLO_RETURN_IF_ERROR(
        test_enclave_client_->EnterAndRun(enclave_input, &enclave_output));
    return enclave_output
        .GetExtension(
            sgx::sgx_age_remote_assertion_generator_test_enclave_output)
        .sgx_self_identity_output()
        .identity();
  }

  // Resets the SgxAgeRemoteAssertionGenerator instance in the test enclave.
  Status EnclaveResetGenerator() {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    *enclave_input
         .MutableExtension(
             sgx::sgx_age_remote_assertion_generator_test_enclave_input)
         ->mutable_reset_generator_input() = sgx::ResetGeneratorInput();

    return test_enclave_client_->EnterAndRun(enclave_input, &enclave_output);
  }

  // Returns |generator->IsInitialized()| from within the test enclave.
  StatusOr<bool> EnclaveIsInitialized() {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    *enclave_input
         .MutableExtension(
             sgx::sgx_age_remote_assertion_generator_test_enclave_input)
         ->mutable_is_initialized_input() = sgx::IsInitializedInput();

    ASYLO_RETURN_IF_ERROR(
        test_enclave_client_->EnterAndRun(enclave_input, &enclave_output));
    return enclave_output
        .GetExtension(
            sgx::sgx_age_remote_assertion_generator_test_enclave_output)
        .is_initialized_output()
        .is_initialized();
  }

  // Returns |generator->Initialize(config)| from within the test enclave.
  Status EnclaveInitialize(const std::string config) {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    enclave_input
        .MutableExtension(
            sgx::sgx_age_remote_assertion_generator_test_enclave_input)
        ->mutable_initialize_input()
        ->set_config(config);

    return test_enclave_client_->EnterAndRun(enclave_input, &enclave_output);
  }

  // Returns |generator->CreateAssertionOffer()| from within the test enclave.
  StatusOr<AssertionOffer> EnclaveCreateAssertionOffer() {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    *enclave_input
         .MutableExtension(
             sgx::sgx_age_remote_assertion_generator_test_enclave_input)
         ->mutable_create_assertion_offer_input() =
        sgx::CreateAssertionOfferInput::default_instance();
    ASYLO_RETURN_IF_ERROR(
        test_enclave_client_->EnterAndRun(enclave_input, &enclave_output));
    return enclave_output
        .GetExtension(
            sgx::sgx_age_remote_assertion_generator_test_enclave_output)
        .create_assertion_offer_output()
        .offer();
  }

  // Returns |generator->CreateGenerate(request)| from within the test enclave.
  StatusOr<bool> EnclaveCanGenerate(AssertionRequest request) {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    sgx::CanGenerateInput *can_generate_input =
        enclave_input
            .MutableExtension(
                sgx::sgx_age_remote_assertion_generator_test_enclave_input)
            ->mutable_can_generate_input();
    *can_generate_input->mutable_request() = request;
    ASYLO_RETURN_IF_ERROR(
        test_enclave_client_->EnterAndRun(enclave_input, &enclave_output));
    return enclave_output
        .GetExtension(
            sgx::sgx_age_remote_assertion_generator_test_enclave_output)
        .can_generate_output()
        .can_generate();
  }

  // Returns the assertion produced by calling |generator->Generate(user_data,
  // request)| from within the test enclave.
  StatusOr<Assertion> EnclaveGenerate(std::string user_data,
                                      AssertionRequest request) {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    sgx::GenerateInput *generate_input =
        enclave_input
            .MutableExtension(
                sgx::sgx_age_remote_assertion_generator_test_enclave_input)
            ->mutable_generate_input();
    generate_input->set_user_data(user_data);
    *generate_input->mutable_request() = request;
    ASYLO_RETURN_IF_ERROR(
        test_enclave_client_->EnterAndRun(enclave_input, &enclave_output));
    return enclave_output
        .GetExtension(
            sgx::sgx_age_remote_assertion_generator_test_enclave_output)
        .generate_output()
        .assertion();
  }

  static EnclaveManager *enclave_manager_;
  static EnclaveConfig *assertion_generator_enclave_config_;
  static EnclaveClient *assertion_generator_enclave_client_;
  static EnclaveConfig *test_enclave_config_;
  static EnclaveClient *test_enclave_client_;

  static std::string *server_address_;
  static std::vector<Certificate> *root_ca_certificates_;

  std::string config_;
};

EnclaveManager *SgxAgeRemoteAssertionGeneratorTest::enclave_manager_;
EnclaveConfig
    *SgxAgeRemoteAssertionGeneratorTest::assertion_generator_enclave_config_;
EnclaveClient
    *SgxAgeRemoteAssertionGeneratorTest::assertion_generator_enclave_client_;
EnclaveConfig *SgxAgeRemoteAssertionGeneratorTest::test_enclave_config_;
EnclaveClient *SgxAgeRemoteAssertionGeneratorTest::test_enclave_client_;
std::string *SgxAgeRemoteAssertionGeneratorTest::server_address_;
std::vector<Certificate>
    *SgxAgeRemoteAssertionGeneratorTest::root_ca_certificates_;

TEST_F(SgxAgeRemoteAssertionGeneratorTest,
       InitializeFailsWithUnparsableConfig) {
  EXPECT_THAT(EnclaveInitialize(kBadConfig),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
  *authority_config.add_root_ca_certificates() = (*root_ca_certificates_)[0];

  std::string config;
  ASSERT_TRUE(authority_config.SerializeToString(&config));

  EXPECT_THAT(EnclaveInitialize(config),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, InitializeFailsWithNoCerts) {
  SgxAgeRemoteAssertionAuthorityConfig authority_config;
  authority_config.set_server_address(*server_address_);

  std::string config;
  ASSERT_TRUE(authority_config.SerializeToString(&config));

  EXPECT_THAT(EnclaveInitialize(config),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, InitializeFailsWithBadCerts) {
  Certificate certificate;
  certificate.set_format(Certificate::UNKNOWN);
  certificate.set_data(kBadCertData);

  SgxAgeRemoteAssertionAuthorityConfig authority_config;
  authority_config.set_server_address(*server_address_);
  *authority_config.add_root_ca_certificates() = certificate;

  std::string config;
  ASSERT_TRUE(authority_config.SerializeToString(&config));

  EXPECT_THAT(EnclaveInitialize(config),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, OneInitializationSingleThreaded) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));
  EXPECT_THAT(EnclaveInitialize(config_),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, OneInitializationMultiThreaded) {
  constexpr int kNumThreads = 11;

  std::atomic<int> num_initializations(0);
  std::vector<Thread> threads;
  threads.reserve(kNumThreads);

  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([this, &num_initializations] {
      num_initializations += EnclaveInitialize(config_).ok() ? 1 : 0;
    });
  }

  for (auto &thread : threads) {
    thread.Join();
  }

  EXPECT_EQ(num_initializations.load(), 1);
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, IsInitializedState) {
  EXPECT_THAT(EnclaveIsInitialized(), IsOkAndHolds(false));
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));
  EXPECT_THAT(EnclaveIsInitialized(), IsOkAndHolds(true));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GenerateFailsIfNotInitialized) {
  EXPECT_THAT(EnclaveIsInitialized(), IsOkAndHolds(false));
  EXPECT_THAT(EnclaveCanGenerate(AssertionRequest::default_instance()),
              StatusIs(error::GoogleError::FAILED_PRECONDITION));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CreateAssertionOfferSuccess) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  AssertionOffer assertion_offer;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_offer, EnclaveCreateAssertionOffer());

  const AssertionDescription &description = assertion_offer.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), sgx::kSgxAgeRemoteAssertionAuthority);

  sgx::RemoteAssertionOfferAdditionalInfo additional_info;
  ASSERT_TRUE(additional_info.ParseFromString(
      assertion_offer.additional_information()));
  EXPECT_THAT(additional_info.root_ca_certificates(),
              ElementsAre(EqualsProto((*root_ca_certificates_)[0]),
                          EqualsProto((*root_ca_certificates_)[1])));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CanGenerateSuccess) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  // Create a valid AssertionRequest.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request, MakeAssertionRequest());
  EXPECT_THAT(EnclaveCanGenerate(assertion_request), IsOkAndHolds(true));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CanGenerateSuccessCertSubset) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  // Create an assertion request with only one of the two CAs contained within
  // the generator.
  std::vector<Certificate> certificates = {root_ca_certificates_[0]};
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest(&certificates));

  EXPECT_THAT(EnclaveCanGenerate(assertion_request), IsOkAndHolds(true));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, CanGenerateFailureNoCerts) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  std::vector<Certificate> certificates;
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest(&certificates));

  EXPECT_THAT(EnclaveCanGenerate(assertion_request),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest,
       CanGenerateFailureExtraCertInRequest) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  std::vector<Certificate> certificates = *root_ca_certificates_;

  // Add another valid cert into the request.
  Certificate certificate;
  certificate.set_format(Certificate::X509_DER);
  certificate.set_data("I'm a good cert!");
  certificates.push_back(certificate);

  // Create a valid AssertionRequest.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request,
                             MakeAssertionRequest(&certificates));

  EXPECT_THAT(EnclaveCanGenerate(assertion_request), IsOkAndHolds(false));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GenerateFailureBadAssertionRequest) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  // Create an AssertionRequest with bad |additional_info|.
  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request, MakeAssertionRequest());
  assertion_request.set_additional_information(kBadAdditionalInfo);

  Assertion assertion;
  EXPECT_THAT(EnclaveGenerate(kUserData, assertion_request),
              StatusIs(error::GoogleError::INTERNAL));
}

TEST_F(SgxAgeRemoteAssertionGeneratorTest, GenerateSuccess) {
  ASYLO_EXPECT_OK(EnclaveInitialize(config_));

  AssertionRequest assertion_request;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion_request, MakeAssertionRequest());

  SgxIdentity enclave_identity;
  ASYLO_ASSERT_OK_AND_ASSIGN(enclave_identity, EnclaveSgxSelfIdentity());

  // Attempt to generate an assertion 100 times to ensure that re-establishing
  // the gRPC channel to the AGE multiple times does not cause server failures.
  for (int i = 0; i < 100; ++i) {
    Assertion assertion;
    ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                               EnclaveGenerate(kUserData, assertion_request));

    const AssertionDescription &description = assertion.description();
    EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
    EXPECT_EQ(description.authority_type(),
              sgx::kSgxAgeRemoteAssertionAuthority);

    sgx::RemoteAssertion remote_assertion;
    ASSERT_TRUE(remote_assertion.ParseFromString(assertion.assertion()));
    sgx::RemoteAssertionPayload payload;
    ASSERT_TRUE(payload.ParseFromString(remote_assertion.payload()));

    EXPECT_THAT(payload.identity(), EqualsProto(enclave_identity));
    EXPECT_EQ(payload.user_data(), kUserData);
  }
}

}  // namespace
}  // namespace asylo
