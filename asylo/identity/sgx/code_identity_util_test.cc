/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/identity/sgx/code_identity_util.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/attributes.pb.h"
#include "asylo/identity/sgx/attributes_util.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_constants.h"
#include "asylo/identity/sgx/code_identity_test_util.h"
#include "asylo/identity/sgx/fake_enclave.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/proto_format.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/identity/sgx/sgx_identity.pb.h"
#include "asylo/identity/util/sha256_hash.pb.h"
#include "asylo/identity/util/sha256_hash_util.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Not;

// Several of the tests in this file generate random identities / match specs /
// expectations in order to verify their whether they can be parsed. Of these,
// the number of identity variations are the upper bound, since the generation
// process of expectations guarantees that match specs match their respective
// identities. The helper methods in `code_identity_test_util` generate 2^4 = 16
// valid and 4*2*2*3 = 48 invalid SgxIdentity variants.
//
// According to the "coupon collector's problem", the expected number of trials
// to "collect 48 identities" is 214 (n*log(n) + n*gamma + 0.5) with a standard
// deviation of 59.6 (sqrt((pi^2 / 6) * n^2)). Central limit theorem suggests
// that we have >99.7% confidence of seeing every match spec after 214 + 60*3 =
// 394 trials, but simulation shows that this value is closer to 460, suggesting
// that the distribution isn't close enough to normal to approximate with CLT.
// Therefore, 500 seems like a reasonable constant to choose.
//
// See more: https://en.wikipedia.org/wiki/Coupon_collector%27s_problem
constexpr uint32_t kNumRandomParseTrials = 500;

constexpr uint32_t kLongAll0 = 0x0;
constexpr uint32_t kLongAllF = 0xFFFFFFFF;
constexpr uint32_t kLongAll5 = 0x55555555;
constexpr uint64_t kLongLongAllF = 0xFFFFFFFFFFFFFFFFULL;
constexpr uint64_t kLongLongAllA = 0xAAAAAAAAAAAAAAAAULL;
constexpr uint64_t kLongLongAll5 = 0x5555555555555555ULL;
constexpr char kValidCpuSvn[] = "deadbeefdeadbeef";
constexpr char kInvalidCpuSvn[] = "not16bytes";
constexpr char kInvalidString[] = "Invalid String";

// A test fixture is used to ensure naming correctness and future expandability.
class CodeIdentityUtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Sha256HashFromHexString(
        "acedfaceacedfaceacedfaceacedfaceacedfaceacedfaceacedfaceacedface",
        &h_acedface_);
    Sha256HashFromHexString(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        &h_deadbeef_);
    attributes_all_f_.set_flags(kLongLongAllF);
    attributes_all_f_.set_xfrm(kLongLongAllF);
    attributes_all_5_.set_flags(kLongLongAll5);
    attributes_all_5_.set_xfrm(kLongLongAll5);
    attributes_all_a_.set_flags(kLongLongAllA);
    attributes_all_a_.set_xfrm(kLongLongAllA);

    // Create a randomly-initialized FakeEnclave singleton, and use it in all
    // the tests. This is necessary as all tests run as a part of a single
    // process, and consequently share the SelfIdentity singleton.
    enclave_ = Singleton<FakeEnclave, RandomFakeEnclaveFactory>::get();
    if (FakeEnclave::GetCurrentEnclave() == nullptr) {
      FakeEnclave::EnterEnclave(*enclave_);
    }
  }

  SignerAssignedIdentity MakeSignerAssignedIdentity(
      const Sha256HashProto &mrsigner, uint16_t isvprodid, uint16_t isvsvn) {
    SignerAssignedIdentity id;
    *id.mutable_mrsigner() = mrsigner;
    id.set_isvprodid(isvprodid);
    id.set_isvsvn(isvsvn);
    return id;
  }

  CodeIdentity GetMinimalValidCodeIdentity(uint32_t miscselect,
                                           const Attributes &attributes) {
    CodeIdentity id;
    id.set_miscselect(miscselect);
    *id.mutable_attributes() = attributes;
    id.mutable_signer_assigned_identity()->set_isvprodid(0);
    id.mutable_signer_assigned_identity()->set_isvsvn(0);
    return id;
  }

  SgxIdentity GetMinimalValidSgxIdentity(uint32_t miscselect,
                                         const Attributes &attributes) {
    SgxIdentity id;
    *id.mutable_code_identity() =
        GetMinimalValidCodeIdentity(miscselect, attributes);

    return id;
  }

  SgxIdentityMatchSpec GetMinimalValidSgxMatchSpec() {
    SgxIdentityMatchSpec spec;
    CodeIdentityMatchSpec *ci_spec = spec.mutable_code_identity_match_spec();
    SgxMachineConfigurationMatchSpec *mc_spec =
        spec.mutable_machine_configuration_match_spec();

    ci_spec->set_is_mrenclave_match_required(true);
    ci_spec->set_is_mrsigner_match_required(true);
    ci_spec->set_miscselect_match_mask(kLongAllF);
    *ci_spec->mutable_attributes_match_mask() = attributes_all_f_;

    mc_spec->set_is_cpu_svn_match_required(false);
    mc_spec->set_is_sgx_type_match_required(false);
    return spec;
  }

  Sha256HashProto h_acedface_;
  Sha256HashProto h_deadbeef_;
  Attributes attributes_all_0_;
  Attributes attributes_all_f_;
  Attributes attributes_all_5_;
  Attributes attributes_all_a_;
  FakeEnclave *enclave_;
};

TEST_F(CodeIdentityUtilTest, SetSgxIdentityDescription) {
  EnclaveIdentityDescription description;
  SetSgxIdentityDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), kSgxAuthorizationAuthority);
}

TEST_F(CodeIdentityUtilTest, SetSgxLocalAssertionDescription) {
  AssertionDescription description;
  SetSgxLocalAssertionDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), kSgxLocalAssertionAuthority);
}

TEST_F(CodeIdentityUtilTest, SetSgxRemoteAssertionDescription) {
  AssertionDescription description;
  SetSgxRemoteAssertionDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), kSgxRemoteAssertionAuthority);
}

// Tests to verify the correctness of IsValidSignerAssignedIdentity()

TEST_F(CodeIdentityUtilTest, SignerAssignedIdentityValidityPositive1) {
  SignerAssignedIdentity id = MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  EXPECT_TRUE(IsValidSignerAssignedIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SignerAssignedIdentityValidityPositive2) {
  SignerAssignedIdentity id;
  id.set_isvprodid(0);
  id.set_isvsvn(0);
  EXPECT_TRUE(IsValidSignerAssignedIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SignerAssignedIdentityValidityNegative1) {
  SignerAssignedIdentity id;
  *id.mutable_mrsigner() = h_acedface_;
  id.set_isvsvn(0);
  EXPECT_FALSE(IsValidSignerAssignedIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SignerAssignedIdentityValidityNegative2) {
  SignerAssignedIdentity id;
  *id.mutable_mrsigner() = h_acedface_;
  id.set_isvprodid(0);
  EXPECT_FALSE(IsValidSignerAssignedIdentity(id));
}

// Tests to verify the correctness of IsValidCodeIdentity()

TEST_F(CodeIdentityUtilTest, CodeIdentityValidityPositive1) {
  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  EXPECT_TRUE(IsValidCodeIdentity(id));
}

TEST_F(CodeIdentityUtilTest, CodeIdentityValidityPositive2) {
  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  EXPECT_TRUE(IsValidCodeIdentity(id));
}

TEST_F(CodeIdentityUtilTest, CodeIdentityValidityNegative1) {
  CodeIdentity id;
  EXPECT_FALSE(IsValidCodeIdentity(id));
}

TEST_F(CodeIdentityUtilTest, CodeIdentityValidityNegative2) {
  CodeIdentity id;
  id.set_miscselect(kLongAll5);
  EXPECT_FALSE(IsValidCodeIdentity(id));
}

TEST_F(CodeIdentityUtilTest, CodeIdentityValidityNegative3) {
  CodeIdentity id;
  *id.mutable_attributes() = attributes_all_5_;
  EXPECT_FALSE(IsValidCodeIdentity(id));
}

// Tests to verify the correctness of IsValidSgxIdentity()

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityPositive1) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  CodeIdentity *cid = id.mutable_code_identity();
  *cid->mutable_mrenclave() = h_acedface_;
  *cid->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  EXPECT_TRUE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityPositive2) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  EXPECT_TRUE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityPositive3) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  id.mutable_machine_configuration()->clear_cpu_svn();
  EXPECT_TRUE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityNegative1) {
  SgxIdentity id;
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityNegative2) {
  SgxIdentity id;
  CodeIdentity *cid = id.mutable_code_identity();
  cid->set_miscselect(kLongAll5);
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityNegative3) {
  SgxIdentity id;
  CodeIdentity *cid = id.mutable_code_identity();
  *cid->mutable_attributes() = attributes_all_5_;
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityNegative4) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  id.mutable_machine_configuration()->mutable_cpu_svn()->clear_value();
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(CodeIdentityUtilTest, SgxIdentityValidityNegative5) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_machine_configuration()->mutable_cpu_svn()->mutable_value() =
      kInvalidCpuSvn;
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

// Tests to verify the correctness of IsValidMatchSpec()

TEST_F(CodeIdentityUtilTest, MatchSpecValidityPositive) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;
  EXPECT_TRUE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, MatchSpecValidityNegative1) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, MatchSpecValidityNegative2) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, MatchSpecValidityNegative3) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, MatchSpecValidityNegative4) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityPositive) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  EXPECT_TRUE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityPositiveLegacyMatchSpec) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();

  // Clear SgxMachineConfiguration to create a valid legacy match spec.
  spec.clear_machine_configuration_match_spec();
  EXPECT_FALSE(IsValidMatchSpec(spec, /*is_legacy=*/false));
  EXPECT_TRUE(IsValidMatchSpec(spec, /*is_legacy=*/true));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityNegative1) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_is_mrenclave_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityNegative2) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_is_mrsigner_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityNegative3) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_miscselect_match_mask();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityNegative4) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_attributes_match_mask();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityNegative5) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->clear_is_cpu_svn_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(CodeIdentityUtilTest, SgxMatchSpecValidityNegative6) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->clear_is_sgx_type_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

// Tests to verify the correctness of IsValidExpectation()

TEST_F(CodeIdentityUtilTest, ExpectationValidityPositive1) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, ExpectationValidityPositive2) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, ExpectationValidityPositive3) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(false);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, ExpectationValidityPositive4) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, ExpectationValidityNegative1) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, ExpectationValidityNegative2) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, SgxExpectationValidityPositive) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, SgxExpectationValidityPositiveLegacyMatchSpec) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  // Clear SgxMachineConfiguration to create a valid legacy match spec.
  expectation.mutable_match_spec()->clear_machine_configuration_match_spec();
  EXPECT_FALSE(IsValidExpectation(expectation, /*is_legacy=*/false));
  EXPECT_TRUE(IsValidExpectation(expectation, /*is_legacy=*/true));
}

TEST_F(CodeIdentityUtilTest, SgxExpectationValidityNegative1) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->set_is_cpu_svn_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

TEST_F(CodeIdentityUtilTest, SgxExpectationValidityNegative2) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->set_is_sgx_type_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

// Check correctness of expectation-to-identity matching

// Make sure that an CodeIdentity matches itself will all the fields marked
// as *do care*.
TEST_F(CodeIdentityUtilTest, CodeIdentitySelfMatch) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_TRUE(result.ValueOrDie());
}

// Make sure that an SgxIdentity matches itself with all the fields marked
// as *do care*.
TEST_F(CodeIdentityUtilTest, SgxIdentitySelfMatch) {
  SgxIdentityMatchSpec spec;

  CodeIdentityMatchSpec *code_identity_match_spec =
      spec.mutable_code_identity_match_spec();
  code_identity_match_spec->set_is_mrenclave_match_required(true);
  code_identity_match_spec->set_is_mrsigner_match_required(true);
  code_identity_match_spec->set_miscselect_match_mask(kLongAllF);
  *code_identity_match_spec->mutable_attributes_match_mask() =
      attributes_all_f_;

  SgxMachineConfigurationMatchSpec *machine_config_match_spec =
      spec.mutable_machine_configuration_match_spec();
  machine_config_match_spec->set_is_cpu_svn_match_required(false);
  machine_config_match_spec->set_is_sgx_type_match_required(false);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);

  CodeIdentity *code_id = id.mutable_code_identity();
  *code_id->mutable_mrenclave() = h_acedface_;
  *code_id->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxMachineConfiguration *machine_config = id.mutable_machine_configuration();
  *machine_config->mutable_cpu_svn()->mutable_value() = kValidCpuSvn;

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  EXPECT_THAT(MatchIdentityToExpectation(id, expectation), IsOkAndHolds(true));

  // Clear SgxMachineConfiguration to create a valid legacy match spec.
  expectation.mutable_match_spec()->clear_machine_configuration_match_spec();
  EXPECT_THAT(MatchIdentityToExpectation(id, expectation, /*is_legacy=*/false),
              Not(IsOk()));
  EXPECT_THAT(MatchIdentityToExpectation(id, expectation, /*is_legacy=*/true),
              IsOkAndHolds(true));
}

// Make sure that an CodeIdentity matches an expectation when it differs from
// the expectation in *all* do-not-care fields.
TEST_F(CodeIdentityUtilTest, CodeIdentityDifferingDoNotCareFields) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(false);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_ASSERT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_f_);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_TRUE(result.ValueOrDie());
}

// Make sure that an CodeIdentity does not match an expectation that differs
// in mrenclave value when is_mrenclave_match_required is set to true.
TEST_F(CodeIdentityUtilTest, CodeIdentityMrEnclaveMismatch) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(false);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_f_);
  *id.mutable_mrenclave() = h_deadbeef_;
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());
}

// Make sure that an CodeIdentity does not match an expectation that differs
// in signer_assigned_identity.mrsigner value when is_mrsigner_match_required is
// set to true.
TEST_F(CodeIdentityUtilTest, CodeIdentitySignerAssignedIdentityMismatch1) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_f_);
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_deadbeef_, 0, 0);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());
}

// Make sure that an CodeIdentity does not match an expectation that differs
// in signer_assigned_identity.isvprodid value when is_mrsigner_match_required
// is set to either true or false.
TEST_F(CodeIdentityUtilTest, CodeIdentitySignerAssignedIdentityMismatch2) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_f_);
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 1, 0);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());

  // Make sure that the identity does not match expectation even when when
  // is_mrsigner_match_required is set to false.
  expectation.mutable_match_spec()->set_is_mrsigner_match_required(false);
  result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());
}

// Make sure that an CodeIdentity does not match an expectation that has a
// signer_assigned_identity.isvsvn value larger than that of the identity when
// is_mrsigner_match_required is set to either true or false.
TEST_F(CodeIdentityUtilTest, CodeIdentitySignerAssignedIdentityMismatch3) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 1);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_f_);
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());

  // Make sure that the identity does not match expectation even when when
  // is_mrsigner_match_required is set to false.
  expectation.mutable_match_spec()->set_is_mrsigner_match_required(false);
  result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());
}

// Make sure that an CodeIdentity *does* match an expectation that has a
// signer_assigned_identity.isvsvn value less than that of the identity when
// is_mrsigner_match_required is set to true.
TEST_F(CodeIdentityUtilTest, CodeIdentitySignerAssignedIdentitySVNMatch) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_f_);
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 1);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_TRUE(result.ValueOrDie());
}

// Make sure that an CodeIdentity does not match an expectation that differs
// from the expectation in the do-care bits of miscselect.
TEST_F(CodeIdentityUtilTest, CodeIdentityMiscSelectMismatch) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(false);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAll0, attributes_all_f_);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());
}

// Make sure that an CodeIdentity does not match an expectation
// that differs from the expectation in the do-care bits of attributes.
TEST_F(CodeIdentityUtilTest, CodeIdentityAttributesMismatch) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(false);
  spec.set_is_mrsigner_match_required(false);
  spec.set_miscselect_match_mask(kLongAll5);
  *spec.mutable_attributes_match_mask() = attributes_all_5_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id = GetMinimalValidCodeIdentity(kLongAllF, attributes_all_0_);
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  ASYLO_ASSERT_OK(result);
  EXPECT_FALSE(result.ValueOrDie());
}

// Make sure that enclave identity match fails with appropriate status if the
// target expectation is invalid.
TEST_F(CodeIdentityUtilTest, CodeIdentityMatchInvalidExpectation) {
  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  EXPECT_EQ(result.status(),
            Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                   "Expectation parameter is invalid"));
}

// Make sure that enclave identity match fails with appropriate status if the
// target identity is invalid.
TEST_F(CodeIdentityUtilTest, CodeIdentityMatchInvalidIdentity) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_mrenclave() = h_acedface_;
  *id.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  id.Clear();
  StatusOr<bool> result = MatchIdentityToExpectation(id, expectation);
  EXPECT_EQ(result.status(),
            Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                   "Identity parameter is invalid"));
}

// Make sure that enclave identity match fails with appropriate status if
// match_spec.mrenclave_match_required is true, but the target identity is
// missing mrenclave.
TEST_F(CodeIdentityUtilTest, CodeIdentityMatchIdentityMissingMrenclave) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id1 = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id1.mutable_mrenclave() = h_acedface_;
  *id1.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id1, &expectation));

  CodeIdentity id2 = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id2.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  StatusOr<bool> result = MatchIdentityToExpectation(id2, expectation);
  EXPECT_EQ(result.status(),
            Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                   "Identity is not compatible with specified match spec"));
}

// Make sure that enclave identity match fails with appropriate status if
// match_spec.mrsigner is true, but the target identity is missing mrsigner.
TEST_F(CodeIdentityUtilTest, CodeIdentityMatchIdentityMissingMrsigner) {
  CodeIdentityMatchSpec spec;
  spec.set_is_mrenclave_match_required(true);
  spec.set_is_mrsigner_match_required(true);
  spec.set_miscselect_match_mask(kLongAllF);
  *spec.mutable_attributes_match_mask() = attributes_all_f_;

  CodeIdentity id1 = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id1.mutable_mrenclave() = h_acedface_;
  *id1.mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id1, &expectation));

  CodeIdentity id2 = GetMinimalValidCodeIdentity(kLongAll5, attributes_all_5_);
  *id2.mutable_mrenclave() = h_acedface_;

  StatusOr<bool> result = MatchIdentityToExpectation(id2, expectation);
  EXPECT_EQ(result.status(),
            Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                   "Identity is not compatible with specified match spec"));
}

TEST_F(CodeIdentityUtilTest, ParseIdentityFromHardwareReport) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr reportdata;
  AlignedReportPtr report;

  *tinfo = TrivialZeroObject<Targetinfo>();
  *reportdata = TrivialZeroObject<Reportdata>();

  ASYLO_EXPECT_OK(GetHardwareReport(*tinfo, *reportdata, report.get()));

  CodeIdentity identity;
  ASYLO_EXPECT_OK(ParseIdentityFromHardwareReport(*report, &identity));
  EXPECT_TRUE(std::equal(
      report->body.mrenclave.cbegin(), report->body.mrenclave.cend(),
      identity.mrenclave().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_TRUE(std::equal(
      report->body.mrsigner.cbegin(), report->body.mrsigner.cend(),
      identity.signer_assigned_identity().mrsigner().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_EQ(report->body.isvprodid,
            identity.signer_assigned_identity().isvprodid());
  EXPECT_EQ(report->body.isvsvn, identity.signer_assigned_identity().isvsvn());

  SecsAttributeSet attributes;
  EXPECT_TRUE(
      ConvertSecsAttributeRepresentation(identity.attributes(), &attributes));
  EXPECT_EQ(report->body.attributes, attributes);
  EXPECT_EQ(report->body.miscselect, identity.miscselect());
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentityFromHardwareReport) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr reportdata;
  AlignedReportPtr report;

  *tinfo = TrivialZeroObject<Targetinfo>();
  *reportdata = TrivialZeroObject<Reportdata>();

  ASYLO_ASSERT_OK(GetHardwareReport(*tinfo, *reportdata, report.get()));

  SgxIdentity identity;
  ASYLO_ASSERT_OK(ParseIdentityFromHardwareReport(*report, &identity));
  CodeIdentity code_identity = identity.code_identity();
  EXPECT_TRUE(std::equal(
      report->body.mrenclave.cbegin(), report->body.mrenclave.cend(),
      code_identity.mrenclave().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_TRUE(std::equal(
      report->body.mrsigner.cbegin(), report->body.mrsigner.cend(),
      code_identity.signer_assigned_identity().mrsigner().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_EQ(report->body.isvprodid,
            code_identity.signer_assigned_identity().isvprodid());
  EXPECT_EQ(report->body.isvsvn,
            code_identity.signer_assigned_identity().isvsvn());

  SecsAttributeSet attributes;
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(code_identity.attributes(),
                                                 &attributes));
  EXPECT_EQ(report->body.attributes, attributes);
  EXPECT_EQ(report->body.miscselect, code_identity.miscselect());

  CpuSvn report_cpusvn;
  report_cpusvn.set_value(report->body.cpusvn.data(),
                          report->body.cpusvn.size());
  EXPECT_THAT(identity.machine_configuration().cpu_svn(),
              EqualsProto(report_cpusvn));
}

TEST_F(CodeIdentityUtilTest, SetDefaultMatchSpec) {
  CodeIdentityMatchSpec spec;
  ASYLO_ASSERT_OK(SetDefaultMatchSpec(&spec));
  EXPECT_FALSE(spec.is_mrenclave_match_required());
  EXPECT_TRUE(spec.is_mrsigner_match_required());
  EXPECT_EQ(spec.miscselect_match_mask(), kLongAllF);
  SecsAttributeSet attributes;
  EXPECT_TRUE(GetDefaultDoNotCareSecsAttributes(&attributes));

  Attributes default_attributes_mask;
  ConvertSecsAttributeRepresentation(~attributes, &default_attributes_mask);
  EXPECT_EQ(spec.attributes_match_mask(), default_attributes_mask);
}

TEST_F(CodeIdentityUtilTest, SetDefaultSgxIdentityMatchSpec) {
  SgxIdentityMatchSpec spec;
  ASYLO_ASSERT_OK(SetDefaultMatchSpec(&spec));
  EXPECT_FALSE(spec.code_identity_match_spec().is_mrenclave_match_required());
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrsigner_match_required());
  EXPECT_EQ(spec.code_identity_match_spec().miscselect_match_mask(), kLongAllF);
  SecsAttributeSet attributes;
  EXPECT_TRUE(GetDefaultDoNotCareSecsAttributes(&attributes));

  Attributes default_attributes_mask;
  ConvertSecsAttributeRepresentation(~attributes, &default_attributes_mask);
  EXPECT_EQ(spec.code_identity_match_spec().attributes_match_mask(),
            default_attributes_mask);

  EXPECT_FALSE(
      spec.machine_configuration_match_spec().is_cpu_svn_match_required());
}

TEST_F(CodeIdentityUtilTest, SetStrictMatchSpec) {
  CodeIdentityMatchSpec spec;
  SetStrictMatchSpec(&spec);
  EXPECT_TRUE(spec.is_mrenclave_match_required());
  EXPECT_TRUE(spec.is_mrsigner_match_required());
  EXPECT_EQ(spec.miscselect_match_mask(), kLongAllF);

  Attributes expected_attributes;
  SetStrictSecsAttributesMask(&expected_attributes);
  EXPECT_EQ(spec.attributes_match_mask(), expected_attributes);
}

TEST_F(CodeIdentityUtilTest, SetStrictSgxIdentityMatchSpec) {
  SgxIdentityMatchSpec spec;
  SetStrictMatchSpec(&spec);
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrenclave_match_required());
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrsigner_match_required());
  EXPECT_EQ(spec.code_identity_match_spec().miscselect_match_mask(), kLongAllF);

  Attributes expected_attributes;
  SetStrictSecsAttributesMask(&expected_attributes);
  EXPECT_EQ(spec.code_identity_match_spec().attributes_match_mask(),
            expected_attributes);

  EXPECT_TRUE(
      spec.machine_configuration_match_spec().is_cpu_svn_match_required());
  EXPECT_TRUE(
      spec.machine_configuration_match_spec().is_sgx_type_match_required());
}

TEST_F(CodeIdentityUtilTest, SetSelfCodeIdentity) {
  CodeIdentity identity;
  SetSelfCodeIdentity(&identity);
  EXPECT_TRUE(std::equal(
      enclave_->get_mrenclave().cbegin(), enclave_->get_mrenclave().cend(),
      identity.mrenclave().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_TRUE(std::equal(
      enclave_->get_mrsigner().cbegin(), enclave_->get_mrsigner().cend(),
      identity.signer_assigned_identity().mrsigner().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_EQ(enclave_->get_isvprodid(),
            identity.signer_assigned_identity().isvprodid());
  EXPECT_EQ(enclave_->get_isvsvn(),
            identity.signer_assigned_identity().isvsvn());

  SecsAttributeSet attributes;
  EXPECT_TRUE(
      ConvertSecsAttributeRepresentation(identity.attributes(), &attributes));
  EXPECT_EQ(enclave_->get_attributes(), attributes);
  EXPECT_EQ(enclave_->get_miscselect(), identity.miscselect());
}

TEST_F(CodeIdentityUtilTest, SetStrictSelfCodeIdentityExpectation) {
  CodeIdentityExpectation expectation;
  SetStrictSelfCodeIdentityExpectation(&expectation);

  CodeIdentityMatchSpec match_spec;
  SetStrictMatchSpec(&match_spec);

  EXPECT_THAT(expectation.reference_identity(),
              EquivalentProto(GetSelfIdentity()->sgx_identity.code_identity()))
      << FormatProto(expectation.reference_identity())
      << FormatProto(GetSelfIdentity()->sgx_identity.code_identity());
  EXPECT_THAT(expectation.match_spec(), EquivalentProto(match_spec))
      << FormatProto(expectation.match_spec()) << FormatProto(match_spec);
}

TEST_F(CodeIdentityUtilTest, SetStrictSelfSgxIdentityExpectation) {
  SgxIdentityExpectation expectation;
  SetStrictSelfSgxIdentityExpectation(&expectation);

  SgxIdentityMatchSpec match_spec;
  SetStrictMatchSpec(&match_spec);

  EXPECT_THAT(expectation.reference_identity(),
              EquivalentProto(GetSelfIdentity()->sgx_identity))
      << FormatProto(expectation.reference_identity())
      << FormatProto(GetSelfIdentity()->sgx_identity);
  EXPECT_THAT(expectation.match_spec(), EquivalentProto(match_spec))
      << FormatProto(expectation.match_spec()) << FormatProto(match_spec);
}

TEST_F(CodeIdentityUtilTest, SetDefaultSelfCodeIdentityExpectation) {
  CodeIdentity identity;
  SetSelfCodeIdentity(&identity);

  CodeIdentityMatchSpec spec;
  ASYLO_EXPECT_OK(SetDefaultMatchSpec(&spec));

  CodeIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetDefaultSelfCodeIdentityExpectation(&expectation));

  EXPECT_THAT(expectation.reference_identity(), EquivalentProto(identity))
      << FormatProto(expectation.reference_identity()) << FormatProto(identity);
  EXPECT_THAT(expectation.match_spec(), EquivalentProto(spec))
      << FormatProto(expectation.match_spec()) << FormatProto(spec);
}

TEST_F(CodeIdentityUtilTest, SetDefaultSelfSgxIdentityExpectation) {
  SgxIdentity identity;
  SetSelfSgxIdentity(&identity);

  SgxIdentityMatchSpec spec;
  ASYLO_ASSERT_OK(SetDefaultMatchSpec(&spec));

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetDefaultSelfSgxIdentityExpectation(&expectation));

  EXPECT_THAT(expectation.reference_identity(), EquivalentProto(identity))
      << FormatProto(expectation.reference_identity()) << FormatProto(identity);
  EXPECT_THAT(expectation.match_spec(), EquivalentProto(spec))
      << FormatProto(expectation.match_spec()) << FormatProto(spec);
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentitySuccess1) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    CodeIdentity generated_sgx_identity;
    SetRandomValidGenericIdentity(&generic_identity, &generated_sgx_identity);
    CodeIdentity parsed_sgx_identity;
    ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
    ASSERT_THAT(generated_sgx_identity, EquivalentProto(parsed_sgx_identity))
        << FormatProto(generated_sgx_identity)
        << FormatProto(parsed_sgx_identity);
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentitySuccess2) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    SgxIdentity generated_sgx_identity;
    ASYLO_ASSERT_OK(SetRandomValidLegacyGenericIdentity(
        &generic_identity, &generated_sgx_identity));
    SgxIdentity parsed_sgx_identity;
    ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
    ASSERT_THAT(generated_sgx_identity, EquivalentProto(parsed_sgx_identity))
        << FormatProto(generated_sgx_identity)
        << FormatProto(parsed_sgx_identity);
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentitySuccess3) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    SgxIdentity generated_sgx_identity;
    ASYLO_ASSERT_OK(SetRandomValidSgxGenericIdentity(&generic_identity,
                                                     &generated_sgx_identity));
    SgxIdentity parsed_sgx_identity;
    ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
    ASSERT_THAT(generated_sgx_identity, EquivalentProto(parsed_sgx_identity))
        << FormatProto(generated_sgx_identity)
        << FormatProto(parsed_sgx_identity);
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentityFailure1) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    SetRandomInvalidGenericIdentity(&generic_identity);
    CodeIdentity parsed_sgx_identity;
    ASSERT_THAT(ParseSgxIdentity(generic_identity, &parsed_sgx_identity),
                Not(IsOk()));
  }
}

// Parse legacy CodeIdentity-based EnclaveIdentity messages into SgxIdentity.
TEST_F(CodeIdentityUtilTest, ParseSgxIdentityFailure2) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    SetRandomInvalidGenericIdentity(&generic_identity);
    SgxIdentity parsed_sgx_identity;
    ASSERT_THAT(ParseSgxIdentity(generic_identity, &parsed_sgx_identity),
                Not(IsOk()));
  }
}

// Parse SgxIdentity-based EnclaveIdentity messages into SgxIdentity.
TEST_F(CodeIdentityUtilTest, ParseSgxIdentityFailure3) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    ASYLO_ASSERT_OK(SetRandomInvalidGenericSgxIdentity(&generic_identity));
    SgxIdentity parsed_sgx_identity;
    ASSERT_THAT(ParseSgxIdentity(generic_identity, &parsed_sgx_identity),
                Not(IsOk()));
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxMatchSpecSuccess) {
  std::string generic_match_spec;
  CodeIdentityMatchSpec generated_sgx_spec;
  CodeIdentityMatchSpec parsed_sgx_spec;

  for (int i = 0; i < kNumRandomParseTrials; i++) {
    ASYLO_ASSERT_OK(SetRandomValidGenericMatchSpec(&generic_match_spec,
                                                   &generated_sgx_spec));
    ASYLO_ASSERT_OK(ParseSgxMatchSpec(generic_match_spec, &parsed_sgx_spec));

    ASSERT_THAT(generated_sgx_spec, EquivalentProto(parsed_sgx_spec))
        << FormatProto(parsed_sgx_spec) << FormatProto(generated_sgx_spec);
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxMatchSpecFailure) {
  std::string generic_match_spec;
  CodeIdentityMatchSpec parsed_sgx_spec;

  for (int i = 0; i < kNumRandomParseTrials; i++) {
    ASYLO_ASSERT_OK(SetRandomInvalidGenericMatchSpec(&generic_match_spec));
    ASSERT_THAT(ParseSgxMatchSpec(generic_match_spec, &parsed_sgx_spec),
                Not(IsOk()));
  }
  generic_match_spec = kInvalidString;
  EXPECT_THAT(ParseSgxMatchSpec(generic_match_spec, &parsed_sgx_spec),
              Not(IsOk()));
}

TEST_F(CodeIdentityUtilTest, ParseSgxExpectationSuccess) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentityExpectation generic_expectation;
    CodeIdentityExpectation generated_sgx_expectation;

    ASYLO_ASSERT_OK(SetRandomValidGenericExpectation(
        &generic_expectation, &generated_sgx_expectation));
    CodeIdentityExpectation parsed_sgx_expectation;
    ASYLO_ASSERT_OK(
        ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation));
    ASSERT_THAT(generated_sgx_expectation,
                EquivalentProto(parsed_sgx_expectation))
        << FormatProto(generated_sgx_expectation)
        << FormatProto(parsed_sgx_expectation);
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentityExpectationSuccess) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentityExpectation generic_expectation;
    SgxIdentityExpectation generated_sgx_expectation;

    ASYLO_ASSERT_OK(SetRandomValidGenericExpectation(
        &generic_expectation, &generated_sgx_expectation));
    SgxIdentityExpectation parsed_sgx_expectation;
    ASYLO_ASSERT_OK(
        ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation));
    ASSERT_THAT(generated_sgx_expectation,
                EquivalentProto(parsed_sgx_expectation))
        << FormatProto(generated_sgx_expectation)
        << FormatProto(parsed_sgx_expectation);
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxExpectationFailure) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentityExpectation generic_expectation;

    ASYLO_ASSERT_OK(SetRandomInvalidGenericExpectation(&generic_expectation));
    CodeIdentityExpectation parsed_sgx_expectation;
    ASSERT_THAT(
        ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation),
        Not(IsOk()));
  }
}

TEST_F(CodeIdentityUtilTest, ParseSgxIdentityExpectationFailure) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentityExpectation generic_expectation;

    ASYLO_ASSERT_OK(SetRandomInvalidGenericExpectation(&generic_expectation));
    SgxIdentityExpectation parsed_sgx_expectation;
    ASSERT_THAT(
        ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation),
        Not(IsOk()));
  }
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseCodeIdentityEndToEnd) {
  CodeIdentity generated_sgx_identity;
  EnclaveIdentity generic_identity;

  EXPECT_THAT(SerializeSgxIdentity(generated_sgx_identity, &generic_identity),
              Not(IsOk()));
  generated_sgx_identity = GetRandomValidCodeIdentity();
  ASYLO_EXPECT_OK(
      SerializeSgxIdentity(generated_sgx_identity, &generic_identity));
  CodeIdentity parsed_sgx_identity;
  ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
  ASSERT_THAT(generated_sgx_identity, EquivalentProto(parsed_sgx_identity))
      << FormatProto(generated_sgx_identity)
      << FormatProto(parsed_sgx_identity);
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseLegacySgxIdentityEndToEnd) {
  SgxIdentity generated_sgx_identity;
  EnclaveIdentity generic_identity;

  EXPECT_THAT(SerializeSgxIdentity(generated_sgx_identity, &generic_identity),
              Not(IsOk()));
  CodeIdentity generated_code_identity = GetRandomValidCodeIdentity();
  ASYLO_ASSERT_OK(
      SerializeSgxIdentity(generated_code_identity, &generic_identity));
  SgxIdentity parsed_sgx_identity;
  ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
  ASSERT_THAT(generated_code_identity,
              EquivalentProto(parsed_sgx_identity.code_identity()))
      << FormatProto(generated_code_identity)
      << FormatProto(parsed_sgx_identity.code_identity());
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseSgxIdentityEndToEnd) {
  SgxIdentity generated_sgx_identity;
  EnclaveIdentity generic_identity;

  EXPECT_THAT(SerializeSgxIdentity(generated_sgx_identity, &generic_identity),
              Not(IsOk()));
  generated_sgx_identity = GetRandomValidSgxIdentity();
  ASYLO_ASSERT_OK(
      SerializeSgxIdentity(generated_sgx_identity, &generic_identity));
  SgxIdentity parsed_sgx_identity;
  ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
  ASSERT_THAT(generated_sgx_identity, EquivalentProto(parsed_sgx_identity))
      << FormatProto(generated_sgx_identity)
      << FormatProto(parsed_sgx_identity);
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseSgxMatchSpecEndToEnd) {
  CodeIdentityMatchSpec generated_sgx_spec;
  std::string generic_spec;

  EXPECT_THAT(SerializeSgxMatchSpec(generated_sgx_spec, &generic_spec),
              Not(IsOk()));
  generated_sgx_spec = GetRandomValidMatchSpec();
  ASYLO_EXPECT_OK(SerializeSgxMatchSpec(generated_sgx_spec, &generic_spec));
  CodeIdentityMatchSpec parsed_sgx_spec;
  ASYLO_ASSERT_OK(ParseSgxMatchSpec(generic_spec, &parsed_sgx_spec));
  ASSERT_THAT(generated_sgx_spec, EquivalentProto(parsed_sgx_spec))
      << FormatProto(generated_sgx_spec) << FormatProto(parsed_sgx_spec);
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseSgxIdentityMatchSpecEndToEnd) {
  SgxIdentityMatchSpec generated_sgx_spec;
  std::string generic_spec;

  EXPECT_THAT(SerializeSgxMatchSpec(generated_sgx_spec, &generic_spec),
              Not(IsOk()));
  generated_sgx_spec = GetRandomValidSgxMatchSpec();
  ASYLO_ASSERT_OK(SerializeSgxMatchSpec(generated_sgx_spec, &generic_spec));
  SgxIdentityMatchSpec parsed_sgx_spec;
  ASYLO_ASSERT_OK(ParseSgxMatchSpec(generic_spec, &parsed_sgx_spec));
  ASSERT_THAT(generated_sgx_spec, EquivalentProto(parsed_sgx_spec))
      << FormatProto(generated_sgx_spec) << FormatProto(parsed_sgx_spec);
}

TEST_F(CodeIdentityUtilTest,
       SerializeAndParseLegacySgxIdentityMatchSpecEndToEnd) {
  SgxIdentityMatchSpec generated_sgx_spec;
  std::string generic_spec;
  generated_sgx_spec = GetRandomValidSgxMatchSpec();

  // Clear SgxMachineConfiguration to create a valid legacy match spec.
  generated_sgx_spec.clear_machine_configuration_match_spec();

  ASYLO_ASSERT_OK(SerializeSgxMatchSpec(
      generated_sgx_spec.code_identity_match_spec(), &generic_spec));
  SgxIdentityMatchSpec parsed_sgx_spec;
  EXPECT_THAT(
      ParseSgxMatchSpec(generic_spec, &parsed_sgx_spec, /*is_legacy=*/false),
      Not(IsOk()));
  ASYLO_ASSERT_OK(
      ParseSgxMatchSpec(generic_spec, &parsed_sgx_spec, /*is_legacy=*/true));
  ASSERT_THAT(parsed_sgx_spec, EquivalentProto(generated_sgx_spec))
      << FormatProto(parsed_sgx_spec) << FormatProto(generated_sgx_spec);
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseSgxExpectationEndToEnd) {
  CodeIdentityExpectation generated_sgx_expectation;
  EnclaveIdentityExpectation generic_expectation;

  EXPECT_THAT(
      SerializeSgxExpectation(generated_sgx_expectation, &generic_expectation),
      Not(IsOk()));
  generated_sgx_expectation = GetRandomValidExpectation();
  ASYLO_EXPECT_OK(
      SerializeSgxExpectation(generated_sgx_expectation, &generic_expectation));
  CodeIdentityExpectation parsed_sgx_expectation;
  ASYLO_ASSERT_OK(
      ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation));
  ASSERT_THAT(generated_sgx_expectation,
              EquivalentProto(parsed_sgx_expectation))
      << FormatProto(generated_sgx_expectation)
      << FormatProto(parsed_sgx_expectation);
}

TEST_F(CodeIdentityUtilTest, SerializeAndParseSgxIdentityExpectationEndToEnd) {
  SgxIdentityExpectation generated_sgx_expectation;
  EnclaveIdentityExpectation generic_expectation;

  EXPECT_THAT(
      SerializeSgxExpectation(generated_sgx_expectation, &generic_expectation),
      Not(IsOk()));
  generated_sgx_expectation = GetRandomValidSgxExpectation();
  ASYLO_ASSERT_OK(
      SerializeSgxExpectation(generated_sgx_expectation, &generic_expectation));
  SgxIdentityExpectation parsed_sgx_expectation;
  ASYLO_ASSERT_OK(
      ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation));
  ASSERT_THAT(generated_sgx_expectation,
              EquivalentProto(parsed_sgx_expectation))
      << FormatProto(generated_sgx_expectation)
      << FormatProto(parsed_sgx_expectation);
}

TEST_F(CodeIdentityUtilTest,
       SerializeAndParseLegacySgxIdentityExpectationEndToEnd) {
  SgxIdentityExpectation generated_sgx_expectation =
      GetRandomValidSgxExpectation();
  EnclaveIdentityExpectation generic_expectation;

  // Clear SgxMachineConfiguration to create a valid legacy expectation.
  generated_sgx_expectation.mutable_reference_identity()
      ->clear_machine_configuration();
  generated_sgx_expectation.mutable_match_spec()
      ->clear_machine_configuration_match_spec();

  CodeIdentityExpectation generated_code_expectation;
  *generated_code_expectation.mutable_reference_identity() =
      generated_sgx_expectation.reference_identity().code_identity();
  *generated_code_expectation.mutable_match_spec() =
      generated_sgx_expectation.match_spec().code_identity_match_spec();

  ASYLO_ASSERT_OK(SerializeSgxExpectation(generated_code_expectation,
                                          &generic_expectation));

  SgxIdentityExpectation parsed_sgx_expectation;
  EXPECT_THAT(ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation,
                                  /*is_legacy=*/false),
              Not(IsOk()));
  ASYLO_ASSERT_OK(ParseSgxExpectation(
      generic_expectation, &parsed_sgx_expectation, /*is_legacy=*/true));
  ASSERT_THAT(parsed_sgx_expectation,
              EquivalentProto(generated_sgx_expectation))
      << FormatProto(parsed_sgx_expectation)
      << FormatProto(generated_sgx_expectation);
}

TEST_F(CodeIdentityUtilTest, SetTargetinfoFromSelfIdentity) {
  AlignedTargetinfoPtr tinfo;
  SetTargetinfoFromSelfIdentity(tinfo.get());

  const SelfIdentity *self_identity = GetSelfIdentity();
  EXPECT_EQ(tinfo->measurement, self_identity->mrenclave);
  EXPECT_EQ(tinfo->attributes, self_identity->attributes);
  EXPECT_EQ(tinfo->miscselect, self_identity->miscselect);
  EXPECT_EQ(tinfo->reserved1,
            TrivialZeroObject<UnsafeBytes<sizeof(tinfo->reserved1)>>());
  EXPECT_EQ(tinfo->reserved2,
            TrivialZeroObject<UnsafeBytes<sizeof(tinfo->reserved2)>>());
}

TEST_F(CodeIdentityUtilTest, VerifyHardwareReportPositive) {
  AlignedTargetinfoPtr tinfo;
  SetTargetinfoFromSelfIdentity(tinfo.get());

  AlignedReportPtr report;
  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();
  ASYLO_ASSERT_OK(GetHardwareReport(*tinfo, *data, report.get()));
  ASYLO_EXPECT_OK(VerifyHardwareReport(*report));
}

TEST_F(CodeIdentityUtilTest, VerifyHardwareReportWrongTarget) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportPtr report;
  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();

  // Verify that corrupting MEASUREMENT results in an unverifiable report.
  SetTargetinfoFromSelfIdentity(tinfo.get());
  tinfo->measurement[0] ^= 0xFFFF;
  ASYLO_ASSERT_OK(GetHardwareReport(*tinfo, *data, report.get()));
  EXPECT_THAT(VerifyHardwareReport(*report), Not(IsOk()));
}

TEST_F(CodeIdentityUtilTest, VerifyHardwareReportBadReport) {
  AlignedTargetinfoPtr tinfo;
  SetTargetinfoFromSelfIdentity(tinfo.get());

  AlignedReportPtr report;
  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();
  ASYLO_ASSERT_OK(GetHardwareReport(*tinfo, *data, report.get()));
  // Corrupt the REPORT by flipping the first byte of MRENCLAVE.
  report->body.mrenclave[0] ^= 0xFFFF;
  EXPECT_THAT(VerifyHardwareReport(*report), Not(IsOk()));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
