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

#include "asylo/identity/attestation/sgx/sgx_local_assertion_verifier.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"
#include "asylo/identity/attestation/sgx/internal/local_assertion.pb.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kBadConfig[] = "Not a real config";

constexpr char kLocalAttestationDomain1[] = "A 16-byte string";
constexpr char kLocalAttestationDomain2[] = "A superb string!";

constexpr char kBadAuthority[] = "Foobar Assertion Authority";
constexpr char kBadAdditionalInfo[] = "Invalid additional info";
constexpr char kBadLocalAssertion[] = "Invalid local assertion";
constexpr char kBadReport[] = "Invalid report";

const char kUserData[] = "User data";

// A test fixture is used to contain common test setup logic and utility
// methods.
class SgxLocalAssertionVerifierTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SgxLocalAssertionAuthorityConfig authority_config;
    authority_config.set_attestation_domain(kLocalAttestationDomain1);
    ASSERT_TRUE(authority_config.SerializeToString(&config_));
  }

  // Sets |description| to the assertion description handled by the SGX local
  // assertion verifier.
  void SetAssertionDescription(AssertionDescription *description) {
    SetAssertionDescription(CODE_IDENTITY, sgx::kSgxLocalAssertionAuthority,
                            description);
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

  // Creates an assertion offer for the SGX local assertion verifier with the
  // given |local_attestation_domain| and places the result in |offer|.
  bool MakeAssertionOffer(absl::string_view local_attestation_domain,
                          AssertionOffer *offer) {
    SetAssertionDescription(offer->mutable_description());

    sgx::LocalAssertionOfferAdditionalInfo additional_info;
    additional_info.set_local_attestation_domain(
        local_attestation_domain.data(), local_attestation_domain.size());

    return additional_info.SerializeToString(
        offer->mutable_additional_information());
  }

  // The config used to initialize a SgxLocalAssertionVerifier.
  std::string config_;
  std::unique_ptr<sgx::HardwareInterface> hardware_ =
      sgx::HardwareInterface::CreateDefault();
};

// Verify that the SgxLocalAssertionVerifier can be found in the
// AssertionVerifierMap.
TEST_F(SgxLocalAssertionVerifierTest, VerifierFoundInStaticMap) {
  auto authority_id_result = EnclaveAssertionAuthority::GenerateAuthorityId(
      CODE_IDENTITY, sgx::kSgxLocalAssertionAuthority);

  ASYLO_ASSERT_OK(authority_id_result);
  ASSERT_NE(AssertionVerifierMap::GetValue(authority_id_result.value()),
            AssertionVerifierMap::value_end());
}

TEST_F(SgxLocalAssertionVerifierTest, IdentityType) {
  SgxLocalAssertionVerifier verifier;
  EXPECT_EQ(verifier.IdentityType(), CODE_IDENTITY);
}

TEST_F(SgxLocalAssertionVerifierTest, AuthorityType) {
  SgxLocalAssertionVerifier verifier;
  EXPECT_EQ(verifier.AuthorityType(), sgx::kSgxLocalAssertionAuthority);
}

// Verify that Initialize() succeeds only once.
TEST_F(SgxLocalAssertionVerifierTest, InitializeSucceedsOnce) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_EXPECT_OK(verifier.Initialize(config_));
  EXPECT_THAT(verifier.Initialize(config_), Not(IsOk()));
}

// Verify that Initialize() fails if the authority config cannot be parsed.
TEST_F(SgxLocalAssertionVerifierTest, InitializeFailsWithUnparsableConfig) {
  SgxLocalAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(kBadConfig), Not(IsOk()));
}

// Verify that Initialize() fails if the authority config is missing the local
// attestation domain.
TEST_F(SgxLocalAssertionVerifierTest, InitializeFailsMissingAttestationDomain) {
  SgxLocalAssertionAuthorityConfig authority_config;
  ASSERT_TRUE(authority_config.SerializeToString(&config_));

  SgxLocalAssertionVerifier verifier;
  EXPECT_THAT(verifier.Initialize(config_), Not(IsOk()));
}

// Verify that IsInitialized() returns false before initialization, and true
// after initialization.
TEST_F(SgxLocalAssertionVerifierTest, IsInitializedBeforeAfterInitialization) {
  SgxLocalAssertionVerifier verifier;
  EXPECT_FALSE(verifier.IsInitialized());
  ASYLO_EXPECT_OK(verifier.Initialize(config_));
  EXPECT_TRUE(verifier.IsInitialized());
}

// Verify that CreateAssertionRequest fails if the verifier is not yet
// initialized.
TEST_F(SgxLocalAssertionVerifierTest,
       CreateAssertionRequestFailsIfNotInitialized) {
  SgxLocalAssertionVerifier verifier;

  AssertionRequest request;
  EXPECT_THAT(verifier.CreateAssertionRequest(&request), Not(IsOk()));
}

// Verify that CreateAssertionRequest() succeeds after initialization, and
// creates a request with the expected description and with non-empty additional
// information.
TEST_F(SgxLocalAssertionVerifierTest, CreateAssertionRequestSuccess) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  AssertionRequest request;
  ASYLO_ASSERT_OK(verifier.CreateAssertionRequest(&request));

  const AssertionDescription &description = request.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), sgx::kSgxLocalAssertionAuthority);

  sgx::LocalAssertionRequestAdditionalInfo additional_info;
  ASSERT_TRUE(
      additional_info.ParseFromString(request.additional_information()));
  EXPECT_EQ(additional_info.local_attestation_domain(),
            kLocalAttestationDomain1);
}

// Verify that CanVerify fails if the verifier is not yet initialized.
TEST_F(SgxLocalAssertionVerifierTest, CanVerifyFailsIfNotInitialized) {
  SgxLocalAssertionVerifier verifier;

  AssertionOffer offer;
  MakeAssertionOffer(kLocalAttestationDomain1, &offer);
  EXPECT_THAT(verifier.CanVerify(offer), Not(IsOk()));
}

// Verify that CanVerify() fails if the AssertionOffer is unparseable.
TEST_F(SgxLocalAssertionVerifierTest,
       CanVerifyFailsIfUnparseableAssertionOffer) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  AssertionOffer offer;
  SetAssertionDescription(offer.mutable_description());
  offer.set_additional_information(kBadAdditionalInfo);
  EXPECT_THAT(verifier.CanVerify(offer), Not(IsOk()));
}

// Verify that CanVerify() fails if the AssertionOffer has an incompatible
// assertion description.
TEST_F(SgxLocalAssertionVerifierTest,
       CanVerifyFailsIfIncompatibleAssertionDescription) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  AssertionOffer offer;
  SetAssertionDescription(UNKNOWN_IDENTITY, kBadAuthority,
                          offer.mutable_description());
  EXPECT_THAT(verifier.CanVerify(offer), Not(IsOk()));
}

// Verify that CanVerify() returns false if the AssertionOffer is for a
// non-local attestation domain.
TEST_F(SgxLocalAssertionVerifierTest,
       CanVerifyFailsIfNonMatchingLocalAttestationDomain) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  AssertionOffer offer;
  MakeAssertionOffer(kLocalAttestationDomain2, &offer);

  EXPECT_THAT(verifier.CanVerify(offer), IsOkAndHolds(false));
}

// Verify that Verify() fails if the verifier is not yet initialized.
TEST_F(SgxLocalAssertionVerifierTest, VerifyFailsIfNotInitialized) {
  SgxLocalAssertionVerifier verifier;

  Assertion assertion;
  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &identity), Not(IsOk()));
}

// Verify that Verify() fails if the Assertion has an incompatible assertion
// description.
TEST_F(SgxLocalAssertionVerifierTest,
       VerifyFailsIfIncompatibleAssertionDescription) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  Assertion assertion;
  EnclaveIdentity identity;
  SetAssertionDescription(UNKNOWN_IDENTITY, kBadAuthority,
                          assertion.mutable_description());
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &identity), Not(IsOk()));
}

// Verify that Verify() fails if the Assertion is unparseable.
TEST_F(SgxLocalAssertionVerifierTest, VerifyFailsIfUnparseableAssertion) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  Assertion assertion;
  EnclaveIdentity identity;
  SetAssertionDescription(assertion.mutable_description());
  assertion.set_assertion(kBadLocalAssertion);
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &identity), Not(IsOk()));
}

// Verify that Verify() fails if the embedded REPORT is malformed.
TEST_F(SgxLocalAssertionVerifierTest, VerifyFailsIfReportMalformed) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  Assertion assertion;
  EnclaveIdentity identity;
  SetAssertionDescription(assertion.mutable_description());

  sgx::LocalAssertion local_assertion;
  local_assertion.set_report(kBadReport);
  ASSERT_TRUE(local_assertion.SerializeToString(assertion.mutable_assertion()));

  EXPECT_THAT(verifier.Verify(kUserData, assertion, &identity), Not(IsOk()));
}

// Verify that Verify() fails if the hardware REPORT is unverifiable.
TEST_F(SgxLocalAssertionVerifierTest, VerifyFailsIfReportIsUnverifiable) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  Assertion assertion;
  SetAssertionDescription(assertion.mutable_description());

  sgx::AlignedReportdataPtr reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      reportdata->data,
      AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator()->Generate(
          kUserData));

  // A REPORT with an empty target will not verifiable by this enclave.
  sgx::AlignedTargetinfoPtr targetinfo;
  *targetinfo = TrivialZeroObject<sgx::Targetinfo>();

  sgx::Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             hardware_->GetReport(*targetinfo, *reportdata));
  sgx::LocalAssertion local_assertion;
  local_assertion.set_report(reinterpret_cast<const char *>(&report),
                             sizeof(report));
  ASSERT_TRUE(local_assertion.SerializeToString(assertion.mutable_assertion()));

  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &identity), Not(IsOk()));
}

// Verify that Verify() fails if the assertion is not bound to the provided
// user-data.
TEST_F(SgxLocalAssertionVerifierTest,
       VerifyFailsIfAssertionIsNotBoundToUserData) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  Assertion assertion;
  SetAssertionDescription(assertion.mutable_description());

  // Use a random REPORTDATA, which certainly won't match the expected
  // REPORTDATA value when the user-data is kUserData.
  sgx::AlignedReportdataPtr reportdata;
  *reportdata = TrivialRandomObject<sgx::Reportdata>();

  sgx::AlignedTargetinfoPtr targetinfo;
  sgx::SetTargetinfoFromSelfIdentity(targetinfo.get());

  sgx::Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             hardware_->GetReport(*targetinfo, *reportdata));
  sgx::LocalAssertion local_assertion;
  local_assertion.set_report(reinterpret_cast<const char *>(&report),
                             sizeof(report));
  ASSERT_TRUE(local_assertion.SerializeToString(assertion.mutable_assertion()));

  EnclaveIdentity identity;
  EXPECT_THAT(verifier.Verify(kUserData, assertion, &identity), Not(IsOk()));
}

// Verify that Verify() succeeds when given a valid Assertion, and correctly
// extracts the enclave's SgxIdentity.
TEST_F(SgxLocalAssertionVerifierTest, VerifySuccess) {
  SgxLocalAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(config_));

  Assertion assertion;
  SetAssertionDescription(assertion.mutable_description());

  sgx::AlignedReportdataPtr reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      reportdata->data,
      AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator()->Generate(
          kUserData));

  sgx::AlignedTargetinfoPtr targetinfo;
  sgx::SetTargetinfoFromSelfIdentity(targetinfo.get());

  sgx::Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             hardware_->GetReport(*targetinfo, *reportdata));
  sgx::LocalAssertion local_assertion;
  local_assertion.set_report(reinterpret_cast<const char *>(&report),
                             sizeof(report));
  ASSERT_TRUE(local_assertion.SerializeToString(assertion.mutable_assertion()));

  EnclaveIdentity identity;
  ASYLO_ASSERT_OK(verifier.Verify(kUserData, assertion, &identity));

  const EnclaveIdentityDescription &description = identity.description();
  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), sgx::kSgxAuthorizationAuthority);

  SgxIdentity sgx_identity;
  ASYLO_ASSERT_OK(sgx::ParseSgxIdentity(identity, &sgx_identity));

  // Verify that the extracted SGX identity matches the generator's identity.
  EXPECT_THAT(sgx_identity, EqualsProto(sgx::GetSelfIdentity()->sgx_identity))
      << "Extracted identity:\n"
      << sgx::FormatProto(sgx_identity)
      << "\nExpected identity:\n"
      << sgx::FormatProto(sgx::GetSelfIdentity()->sgx_identity);
}

}  // namespace
}  // namespace asylo
