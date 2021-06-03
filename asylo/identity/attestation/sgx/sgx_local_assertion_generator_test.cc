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

#include "asylo/identity/attestation/sgx/sgx_local_assertion_generator.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/enclave_assertion_generator.h"
#include "asylo/identity/attestation/sgx/internal/local_assertion.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/thread.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Not;

constexpr char kBadConfig[] = "Not a real config";

constexpr char kLocalAttestationDomain1[] = "A 16-byte string";
constexpr char kLocalAttestationDomain2[] = "A superb string!";

constexpr char kBadAuthority[] = "Foobar Assertion Authority";
constexpr char kBadAdditionalInfo[] = "Invalid additional info";

const char kUserData[] = "User data";

// A test fixture is used to contain common test setup logic and utility
// methods.
class SgxLocalAssertionGeneratorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SgxLocalAssertionAuthorityConfig authority_config;
    authority_config.set_attestation_domain(kLocalAttestationDomain1);
    ASSERT_TRUE(authority_config.SerializeToString(&config_));
  }

  // Sets |description| to the assertion description handled by the SGX local
  // assertion generator.
  void SetAssertionDescription(AssertionDescription *description) {
    description->set_identity_type(CODE_IDENTITY);
    description->set_authority_type(sgx::kSgxLocalAssertionAuthority);
  }

  // Sets |description| to a description of the given |identity_type| and
  // |authority_type|.
  void SetAssertionDescription(EnclaveIdentityType identity_type,
                               absl::string_view authority_type,
                               AssertionDescription *description) {
    description->set_identity_type(identity_type);
    description->set_authority_type(authority_type.data(),
                                    authority_type.size());
  }

  // Creates an assertion request for the SGX local assertion generator with the
  // given |targetinfo| and |local_attestation_domain| and places the result in
  // |request|.
  bool MakeAssertionRequest(absl::string_view targetinfo,
                            absl::string_view local_attestation_domain,
                            AssertionRequest *request) {
    SetAssertionDescription(request->mutable_description());

    sgx::LocalAssertionRequestAdditionalInfo additional_info;
    additional_info.set_targetinfo(targetinfo.data(), targetinfo.size());
    additional_info.set_local_attestation_domain(
        local_attestation_domain.data(), local_attestation_domain.size());

    return additional_info.SerializeToString(
        request->mutable_additional_information());
  }

  // Creates an assertion request for the SGX local assertion generator with the
  // given |local_attestation_domain| and a random TARGETINFO and places the
  // result in |request|.
  bool MakeAssertionRequestWithRandomTarget(
      absl::string_view local_attestation_domain, AssertionRequest *request) {
    sgx::Targetinfo targetinfo = TrivialZeroObject<sgx::Targetinfo>();

    // Only randomize the enclave measurement because the other fields in
    // Targetinfo have reserved sections that must be zeroed out.
    targetinfo.measurement =
        TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>();

    return MakeAssertionRequest(
        absl::string_view(reinterpret_cast<const char *>(&targetinfo),
                          sizeof(targetinfo)),
        local_attestation_domain, request);
  }

  // The config used to initialize a SgxLocalAssertionGenerator.
  std::string config_;
};

// Verify that the SgxLocalAssertionGenerator can be found in the
// AssertionGeneratorMap.
TEST_F(SgxLocalAssertionGeneratorTest, GeneratorFoundInStaticMap) {
  auto authority_id_result = EnclaveAssertionAuthority::GenerateAuthorityId(
      CODE_IDENTITY, sgx::kSgxLocalAssertionAuthority);

  ASSERT_THAT(authority_id_result, IsOk());
  ASSERT_NE(AssertionGeneratorMap::GetValue(authority_id_result.value()),
            AssertionGeneratorMap::value_end());
}

// Verify that Initialize() succeeds only once.
TEST_F(SgxLocalAssertionGeneratorTest, InitializeSucceedsOnce) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());
  EXPECT_THAT(generator.Initialize(config_), Not(IsOk()));
}

// Verify that Initialize() succeeds only once, even when called from multiple
// threads.
TEST_F(SgxLocalAssertionGeneratorTest,
       InitializeSucceedsOnceFromMultipleThreads) {
  constexpr int kNumThreads = 10;

  SgxLocalAssertionGenerator generator;
  std::atomic<int> num_initialize_successes(0);
  std::vector<Thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([this, &generator, &num_initialize_successes] {
      num_initialize_successes += generator.Initialize(config_).ok() ? 1 : 0;
    });
  }
  for (auto &thread : threads) {
    thread.Join();
  }
  EXPECT_THAT(num_initialize_successes.load(), Eq(1));
}

// Verify that Initialize() fails if the authority config cannot be parsed.
TEST_F(SgxLocalAssertionGeneratorTest, InitializeFailsWithUnparsableConfig) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(kBadConfig), Not(IsOk()));
}

// Verify that Initialize() fails if local_attestation_domain is not set in the
// authority config.
TEST_F(SgxLocalAssertionGeneratorTest,
       InitializeFailsMissingAttestationDomain) {
  SgxLocalAssertionAuthorityConfig authority_config;
  ASSERT_TRUE(authority_config.SerializeToString(&config_));

  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), Not(IsOk()));
}

// Verify that IsInitialized() returns false before initialization, and true
// after initialization.
TEST_F(SgxLocalAssertionGeneratorTest, IsInitializedBeforeAfterInitialization) {
  SgxLocalAssertionGenerator generator;
  EXPECT_FALSE(generator.IsInitialized());
  EXPECT_THAT(generator.Initialize(config_), IsOk());
  EXPECT_TRUE(generator.IsInitialized());
}

TEST_F(SgxLocalAssertionGeneratorTest, IdentityType) {
  SgxLocalAssertionGenerator generator;
  EXPECT_EQ(generator.IdentityType(), CODE_IDENTITY);
}

TEST_F(SgxLocalAssertionGeneratorTest, AuthorityType) {
  SgxLocalAssertionGenerator generator;
  EXPECT_EQ(generator.AuthorityType(), sgx::kSgxLocalAssertionAuthority);
}

// Verify that CreateAssertionOffer() fails if the generator is not yet
// initialized.
TEST_F(SgxLocalAssertionGeneratorTest,
       CreateAssertionOfferFailsIfNotInitialized) {
  SgxLocalAssertionGenerator generator;
  AssertionOffer assertion_offer;
  EXPECT_THAT(generator.CreateAssertionOffer(&assertion_offer), Not(IsOk()));
}

// Verify that CreateAssertionOffer() succeeds after initialization, and creates
// an offer with the expected description and with non-empty additional
// information.
TEST_F(SgxLocalAssertionGeneratorTest, CreateAssertionOfferSuccess) {
  SgxLocalAssertionGenerator generator;
  ASSERT_THAT(generator.Initialize(config_), IsOk());

  AssertionOffer assertion_offer;
  EXPECT_THAT(generator.CreateAssertionOffer(&assertion_offer), IsOk());

  const AssertionDescription &description = assertion_offer.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), sgx::kSgxLocalAssertionAuthority);

  sgx::LocalAssertionOfferAdditionalInfo additional_info;
  ASSERT_TRUE(additional_info.ParseFromString(
      assertion_offer.additional_information()));
  EXPECT_EQ(additional_info.local_attestation_domain(),
            kLocalAttestationDomain1);
}

// Verify that CanGenerate() fails if the generator is not yet initialized.
TEST_F(SgxLocalAssertionGeneratorTest, CanGenerateFailsIfNotInitialized) {
  SgxLocalAssertionGenerator generator;
  AssertionRequest assertion_request;

  // Create a valid AssertionRequest.
  ASSERT_TRUE(MakeAssertionRequestWithRandomTarget(kLocalAttestationDomain1,
                                                   &assertion_request));

  EXPECT_THAT(generator.CanGenerate(assertion_request), Not(IsOk()));
}

// Verify that CanGenerate() returns false if the AssertionRequest is for a
// non-local attestation domain.
TEST_F(SgxLocalAssertionGeneratorTest,
       CanGenerateFailsIfNonMatchingLocalAttestationDomain) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest assertion_request;

  // Create an AssertionRequest for a non-matching local attestation domain.
  ASSERT_TRUE(MakeAssertionRequestWithRandomTarget(kLocalAttestationDomain2,
                                                   &assertion_request));
  EXPECT_THAT(generator.CanGenerate(assertion_request), IsOkAndHolds(false));
}

// Verify that CanGenerate() fails if the AssertionRequest is unparseable.
TEST_F(SgxLocalAssertionGeneratorTest,
       CanGenerateFailsIfUnparseableAssertionRequest) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest assertion_request;
  SetAssertionDescription(assertion_request.mutable_description());
  assertion_request.set_additional_information(kBadAdditionalInfo);

  EXPECT_THAT(generator.CanGenerate(assertion_request), Not(IsOk()));
}

// Verify that CanGenerate() fails if the AssertionRequest has an incompatible
// assertion description.
TEST_F(SgxLocalAssertionGeneratorTest,
       CanGenerateFailsIfIncompatibleAssertionDescription) {
  SgxLocalAssertionGenerator generator;
  ASSERT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest request;
  SetAssertionDescription(UNKNOWN_IDENTITY, kBadAuthority,
                          request.mutable_description());
  EXPECT_THAT(generator.CanGenerate(request), Not(IsOk()));
}

// Verify that CanGenerate() succeeds when the AssertionRequest is valid and for
// the local attestation domain.
TEST_F(SgxLocalAssertionGeneratorTest, CanGenerateSuccess) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest assertion_request;

  // Create a valid AssertionRequest.
  ASSERT_TRUE(MakeAssertionRequestWithRandomTarget(kLocalAttestationDomain1,
                                                   &assertion_request));
  EXPECT_THAT(generator.CanGenerate(assertion_request), IsOkAndHolds(true));
}

// Verify that Generate() fails if the generator is not yet initialized.
TEST_F(SgxLocalAssertionGeneratorTest, GenerateFailsIfNotInitialized) {
  SgxLocalAssertionGenerator generator;
  AssertionRequest assertion_request;

  // Create a valid AssertionRequest.
  ASSERT_TRUE(MakeAssertionRequestWithRandomTarget(kLocalAttestationDomain1,
                                                   &assertion_request));

  Assertion assertion;
  EXPECT_THAT(generator.Generate(kUserData, assertion_request, &assertion),
              Not(IsOk()));
}

// Verify that Generate() fails if the AssertionRequest has an incompatible
// assertion description.
TEST_F(SgxLocalAssertionGeneratorTest,
       GenerateFailsIfIncompatibleAssertionDescription) {
  SgxLocalAssertionGenerator generator;
  AssertionRequest assertion_request;

  AssertionRequest request;
  SetAssertionDescription(UNKNOWN_IDENTITY, kBadAuthority,
                          request.mutable_description());

  Assertion assertion;
  EXPECT_THAT(generator.Generate(kUserData, request, &assertion), Not(IsOk()));
}

// Verify that Generate() fails if the AssertionRequest is for a non-local
// attestation domain.
TEST_F(SgxLocalAssertionGeneratorTest,
       GenerateFailsIfNonMatchingLocalAttestationDomain) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest assertion_request;

  // Create an AssertionRequest for a non-matching local attestation domain.
  ASSERT_TRUE(MakeAssertionRequestWithRandomTarget(kLocalAttestationDomain2,
                                                   &assertion_request));

  Assertion assertion;
  EXPECT_THAT(generator.Generate(kUserData, assertion_request, &assertion),
              Not(IsOk()));
}

// Verify that Generate() fails if the AssertionRequest is unparseable.
TEST_F(SgxLocalAssertionGeneratorTest,
       GenerateFailsIfUnparseableAssertionRequest) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest assertion_request;
  SetAssertionDescription(assertion_request.mutable_description());
  assertion_request.set_additional_information(kBadAdditionalInfo);

  Assertion assertion;
  EXPECT_THAT(generator.Generate(kUserData, assertion_request, &assertion),
              Not(IsOk()));
}

// Verify that Generate() succeeds when provided a valid AssertionRequest and
// produces an assertion that can be verified by the same enclave.
TEST_F(SgxLocalAssertionGeneratorTest, GenerateSuccess) {
  SgxLocalAssertionGenerator generator;
  EXPECT_THAT(generator.Initialize(config_), IsOk());

  AssertionRequest assertion_request;
  sgx::Targetinfo targetinfo;
  sgx::SetTargetinfoFromSelfIdentity(&targetinfo);

  // Create a valid AssertionRequest that is targeted at the self identity.
  ASSERT_TRUE(MakeAssertionRequest(
      absl::string_view(reinterpret_cast<const char *>(&targetinfo),
                        sizeof(targetinfo)),
      kLocalAttestationDomain1, &assertion_request));

  Assertion assertion;
  ASSERT_THAT(generator.Generate(kUserData, assertion_request, &assertion),
              IsOk());

  const AssertionDescription &description = assertion.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), sgx::kSgxLocalAssertionAuthority);

  // Verify that the report embedded in the assertion can be verified by the
  // same enclave. Note that this structure must be aligned, so AlignedReportPtr
  // is used instead of Report.
  sgx::AlignedReportPtr report;
  sgx::LocalAssertion local_assertion;
  ASSERT_TRUE(local_assertion.ParseFromString(assertion.assertion()));

  ASSERT_THAT(SetTrivialObjectFromBinaryString<sgx::Report>(
                  local_assertion.report(), report.get()),
              IsOk());
  EXPECT_THAT(sgx::VerifyHardwareReport(*report), IsOk())
      << ConvertTrivialObjectToHexString(*report);

  // Verify that the assertion is bound to a hash of the user data.
  UnsafeBytes<kAdditionalAuthenticatedDataSize> expected_reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_reportdata,
      AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator()->Generate(
          kUserData));
  EXPECT_EQ(report->body.reportdata.data, expected_reportdata);

  // Verify that the asserted identity is the self identity.
  SgxIdentity sgx_identity = ParseSgxIdentityFromHardwareReport(report->body);

  SgxIdentity expected_identity = sgx::GetSelfIdentity()->sgx_identity;
  EXPECT_THAT(sgx_identity, EqualsProto(expected_identity))
      << "Extracted identity:\n"
      << sgx_identity.DebugString() << "\nExpected identity:\n"
      << expected_identity.DebugString();
}

}  // namespace
}  // namespace asylo
