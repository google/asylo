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

#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/sha256_hash_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/attributes_util.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_test_util.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::HasSubstr;
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
constexpr char kValidCpuSvn2[] = "f00f00f00f00f00d";
constexpr char kInvalidCpuSvn[] = "not16bytes";
constexpr char kInvalidString[] = "Invalid String";

// A test fixture is used to ensure naming correctness and future expandability.
class SgxIdentityUtilInternalTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        h_acedface_, CreateSha256HashProto("acedfaceacedfaceacedfaceacedface"
                                           "acedfaceacedfaceacedfaceacedface"));
    ASYLO_ASSERT_OK_AND_ASSIGN(
        h_deadbeef_, CreateSha256HashProto("deadbeefdeadbeefdeadbeefdeadbeef"
                                           "deadbeefdeadbeefdeadbeefdeadbeef"));
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
    MachineConfigurationMatchSpec *mc_spec =
        spec.mutable_machine_configuration_match_spec();

    ci_spec->set_is_mrenclave_match_required(false);
    ci_spec->set_is_mrsigner_match_required(false);
    ci_spec->set_miscselect_match_mask(kLongAllF);
    *ci_spec->mutable_attributes_match_mask() = attributes_all_f_;

    mc_spec->set_is_cpu_svn_match_required(false);
    mc_spec->set_is_sgx_type_match_required(false);
    return spec;
  }

  StatusOr<SgxIdentityExpectation> GetMinimalValidSgxExpectation(
      uint32_t miscselect, const Attributes &attributes) {
    SgxIdentityExpectation expectation;
    SgxIdentityMatchSpec match_spec = GetMinimalValidSgxMatchSpec();
    SgxIdentity identity = GetMinimalValidSgxIdentity(miscselect, attributes);
    ASYLO_RETURN_IF_ERROR(SetExpectation(match_spec, identity, &expectation));
    return expectation;
  }

  Sha256HashProto h_acedface_;
  Sha256HashProto h_deadbeef_;
  Attributes attributes_all_0_;
  Attributes attributes_all_f_;
  Attributes attributes_all_5_;
  Attributes attributes_all_a_;
  FakeEnclave *enclave_;
  std::unique_ptr<HardwareInterface> hardware_ =
      HardwareInterface::CreateDefault();
};

TEST_F(SgxIdentityUtilInternalTest, SetSgxIdentityDescription) {
  EnclaveIdentityDescription description;
  SetSgxIdentityDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), kSgxAuthorizationAuthority);
}

TEST_F(SgxIdentityUtilInternalTest, SetSgxLocalAssertionDescription) {
  AssertionDescription description;
  SetSgxLocalAssertionDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), kSgxLocalAssertionAuthority);
}

TEST_F(SgxIdentityUtilInternalTest, SetSgxAgeRemoteAssertionDescription) {
  AssertionDescription description;
  SetSgxAgeRemoteAssertionDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(), kSgxAgeRemoteAssertionAuthority);
}

TEST_F(SgxIdentityUtilInternalTest,
       SetSgxIntelEcdsaQeRemoteAssertionDescription) {
  AssertionDescription description;
  SetSgxIntelEcdsaQeRemoteAssertionDescription(&description);

  EXPECT_EQ(description.identity_type(), CODE_IDENTITY);
  EXPECT_EQ(description.authority_type(),
            kSgxIntelEcdsaQeRemoteAssertionAuthority);
}

// Tests to verify the correctness of IsValidSignerAssignedIdentity()

TEST_F(SgxIdentityUtilInternalTest,
       SignerAssignedIdentityValidityPositiveAllSet) {
  SignerAssignedIdentity id = MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  EXPECT_TRUE(IsValidSignerAssignedIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest,
       SignerAssignedIdentityValidityPositiveNoMrsigner) {
  SignerAssignedIdentity id = MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  id.clear_mrsigner();
  EXPECT_TRUE(IsValidSignerAssignedIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest,
       SignerAssignedIdentityValidityNegativeNoIsvprodid) {
  SignerAssignedIdentity id;
  *id.mutable_mrsigner() = h_acedface_;
  id.set_isvsvn(0);
  EXPECT_FALSE(IsValidSignerAssignedIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest,
       SignerAssignedIdentityValidityNegativeNoIsvsvn) {
  SignerAssignedIdentity id;
  *id.mutable_mrsigner() = h_acedface_;
  id.set_isvprodid(0);
  EXPECT_FALSE(IsValidSignerAssignedIdentity(id));
}

// Tests to verify the correctness of IsValidSgxIdentity()

TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityPositiveAllSet) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  CodeIdentity *cid = id.mutable_code_identity();
  *cid->mutable_mrenclave() = h_acedface_;
  *cid->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);
  EXPECT_TRUE(IsValidSgxIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxIdentityValidityPositiveMinimalIdentity) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  EXPECT_TRUE(IsValidSgxIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityPositiveNoCpusvn) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  id.mutable_machine_configuration()->clear_cpu_svn();
  EXPECT_TRUE(IsValidSgxIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityNegativeEmptyIdentity) {
  SgxIdentity id;
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityNegativeNoMiscselect) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  id.mutable_code_identity()->clear_miscselect();
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityNegativeNoAttributes) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  id.mutable_code_identity()->clear_attributes();
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

// If the MachineConfiguration has the |cpu_svn| field set, it is invalid
// unless it contains a valid CPUSVN. (SgxIdentityValidityPositiveNoCpusvn
// passes because the CPUSVN field is completely missing, which is valid.)
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityNegativeEmptyCpusvn) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  id.mutable_machine_configuration()->mutable_cpu_svn()->clear_value();
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

TEST_F(SgxIdentityUtilInternalTest, SgxIdentityValidityNegativeInvalidCpusvn) {
  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_machine_configuration()->mutable_cpu_svn()->mutable_value() =
      kInvalidCpuSvn;
  EXPECT_FALSE(IsValidSgxIdentity(id));
}

// Tests to verify the correctness of IsValidMatchSpec()

TEST_F(SgxIdentityUtilInternalTest, SgxMatchSpecValidityPositive) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  EXPECT_TRUE(IsValidMatchSpec(spec));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxMatchSpecValidityNegativeMrenclaveUnset) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_is_mrenclave_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(SgxIdentityUtilInternalTest, SgxMatchSpecValidityNegativeMrsignerUnset) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_is_mrsigner_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxMatchSpecValidityNegativeMiscselectUnset) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_miscselect_match_mask();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxMatchSpecValidityNegativeAttributesUnset) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->clear_attributes_match_mask();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(SgxIdentityUtilInternalTest, SgxMatchSpecValidityNegativeCpusvnUnset) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->clear_is_cpu_svn_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

TEST_F(SgxIdentityUtilInternalTest, SgxMatchSpecValidityNegativeSgxTypeUnset) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->clear_is_sgx_type_match_required();
  EXPECT_FALSE(IsValidMatchSpec(spec));
}

// Tests to verify the correctness of IsValidExpectation()

TEST_F(SgxIdentityUtilInternalTest, SgxExpectationValidityPositive) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityPositiveMrenclaveMrsignerMatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->set_is_mrenclave_match_required(
      true);
  spec.mutable_code_identity_match_spec()->set_is_mrsigner_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityPositiveMrsignerMatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->set_is_mrsigner_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityPositiveMrenclaveMatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->set_is_mrenclave_match_required(
      true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_TRUE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityNegativeMrenclaveMismatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->set_is_mrenclave_match_required(
      true);
  spec.mutable_code_identity_match_spec()->set_is_mrsigner_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityNegativeMrsignerMismatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_code_identity_match_spec()->set_is_mrenclave_match_required(
      true);
  spec.mutable_code_identity_match_spec()->set_is_mrsigner_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *id.mutable_code_identity()->mutable_mrenclave() = h_acedface_;

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityNegativeCpusvnMismatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->set_is_cpu_svn_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

TEST_F(SgxIdentityUtilInternalTest,
       SgxExpectationValidityNegativeSgxTypeMismatch) {
  SgxIdentityMatchSpec spec = GetMinimalValidSgxMatchSpec();
  spec.mutable_machine_configuration_match_spec()
      ->set_is_sgx_type_match_required(true);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));
  EXPECT_FALSE(IsValidExpectation(expectation));
}

// Make sure that an SgxIdentity matches itself with all the fields marked
// as *do care*.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentitySelfMatch) {
  SgxIdentityMatchSpec spec;

  CodeIdentityMatchSpec *code_identity_match_spec =
      spec.mutable_code_identity_match_spec();
  code_identity_match_spec->set_is_mrenclave_match_required(true);
  code_identity_match_spec->set_is_mrsigner_match_required(true);
  code_identity_match_spec->set_miscselect_match_mask(kLongAllF);
  *code_identity_match_spec->mutable_attributes_match_mask() =
      attributes_all_f_;

  MachineConfigurationMatchSpec *machine_config_match_spec =
      spec.mutable_machine_configuration_match_spec();
  machine_config_match_spec->set_is_cpu_svn_match_required(false);
  machine_config_match_spec->set_is_sgx_type_match_required(false);

  SgxIdentity id = GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);

  CodeIdentity *code_id = id.mutable_code_identity();
  *code_id->mutable_mrenclave() = h_acedface_;
  *code_id->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  MachineConfiguration *machine_config = id.mutable_machine_configuration();
  *machine_config->mutable_cpu_svn()->mutable_value() = kValidCpuSvn;

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetExpectation(spec, id, &expectation));

  EXPECT_THAT(
      MatchIdentityToExpectation(id, expectation, /*explanation=*/nullptr),
      IsOkAndHolds(true));
}

// Make sure that an SgxIdentity matches an expectation when it differs from
// the expectations in fields that the match spec does not care about.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityDifferingUnrequiredFields) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));

  MachineConfigurationMatchSpec *machine_config_match_spec =
      expectation.mutable_match_spec()
          ->mutable_machine_configuration_match_spec();
  machine_config_match_spec->set_is_cpu_svn_match_required(false);
  machine_config_match_spec->set_is_sgx_type_match_required(false);

  MachineConfiguration *machine_config =
      expectation.mutable_reference_identity()->mutable_machine_configuration();
  machine_config->mutable_cpu_svn()->set_value(kValidCpuSvn);
  machine_config->set_sgx_type(SgxType::STANDARD);

  SgxIdentity identity = expectation.reference_identity();
  identity.mutable_machine_configuration()->mutable_cpu_svn()->set_value(
      kValidCpuSvn2);
  identity.mutable_machine_configuration()->set_sgx_type(
      SgxType::SGX_TYPE_UNKNOWN);

  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation,
                                         /*explanation=*/nullptr),
              IsOkAndHolds(true));
}

// Make sure that an SgxIdentity does not match an expectation that differs
// in MRENCLAVE value when is_mrenclave_match_required is set to true.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityMrenclaveMismatch) {
  SgxIdentityExpectation expectation;
  *expectation.mutable_match_spec() = GetMinimalValidSgxMatchSpec();
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrenclave_match_required(true);
  *expectation.mutable_reference_identity() =
      GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_mrenclave() = h_acedface_;

  SgxIdentity identity = expectation.reference_identity();
  *identity.mutable_code_identity()->mutable_mrenclave() = h_deadbeef_;

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("does not match expected MRENCLAVE"));
}

// Make sure that an SgxIdentity does not match an expectation that differs
// in signer_assigned_identity.mrsigner value when is_mrsigner_match_required is
// set to true.
TEST_F(SgxIdentityUtilInternalTest,
       SgxIdentitySignerAssignedIdentityMrsignerMismatch) {
  SgxIdentityExpectation expectation;
  *expectation.mutable_match_spec() = GetMinimalValidSgxMatchSpec();
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrsigner_match_required(true);
  *expectation.mutable_reference_identity() =
      GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentity identity = expectation.reference_identity();
  *identity.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_deadbeef_, 0, 0);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("does not match expected MRSIGNER value"));
}

// Make sure that an SgxIdentity does not match an expectation that differs
// in signer_assigned_identity.isvprodid value when is_mrsigner_match_required
// is set to either true or false.
TEST_F(SgxIdentityUtilInternalTest,
       SgxIdentitySignerAssignedIdentityIsvprodidMismatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentity identity = expectation.reference_identity();
  *identity.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 1, 0);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation,
              HasSubstr("does not match expected ISVPRODID value"));

  // Make sure that the identity does not match expectation even when
  // is_mrsigner_match_required is set to true.
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrsigner_match_required(true);
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
}

// Make sure that an CodeIdentity does not match an expectation that has a
// signer_assigned_identity.isvsvn value larger than that of the identity when
// is_mrsigner_match_required is set to either true or false.
TEST_F(SgxIdentityUtilInternalTest,
       CodeIdentitySignerAssignedIdentityIsvsvnMismatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 1);

  SgxIdentity identity = expectation.reference_identity();
  *identity.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("is lower than expected ISVSVN"));

  // Make sure that the identity does not match expectation even when
  // is_mrsigner_match_required is set to true.
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrsigner_match_required(true);
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
}

// Make sure that an CodeIdentity *does* match an expectation that has a
// signer_assigned_identity.isvsvn value less than that of the identity when
// is_mrsigner_match_required is set to true.
TEST_F(SgxIdentityUtilInternalTest,
       CodeIdentitySignerAssignedIdentitySvnMatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrsigner_match_required(true);
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentity identity = expectation.reference_identity();
  *identity.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 1);

  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation,
                                         /*explanation=*/nullptr),
              IsOkAndHolds(true));
}

// Make sure that an CodeIdentity does not match an expectation that differs
// from the expectation in the do-care bits of miscselect.
TEST_F(SgxIdentityUtilInternalTest, CodeIdentityMiscSelectMismatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));

  SgxIdentity identity =
      GetMinimalValidSgxIdentity(kLongAll0, attributes_all_5_);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation,
              HasSubstr("does not match expected MISCSELECT value"));
}

// Make sure that an SgxIdentity does not match an expectation
// that differs from the expectation in the do-care bits of attributes.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityAttributesMismatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));

  SgxIdentity identity = expectation.reference_identity();
  *identity.mutable_code_identity()->mutable_attributes() = attributes_all_0_;

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation,
              HasSubstr("does not match expected ATTRIBUTES value"));
}

// Check that an SgxIdentity does not match an expectation with a differing
// CPUSVN value when CPUSVN match is required.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityCpusvnMismatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));

  // Require a match on CPUSVN.
  expectation.mutable_match_spec()
      ->mutable_machine_configuration_match_spec()
      ->set_is_cpu_svn_match_required(true);
  expectation.mutable_reference_identity()
      ->mutable_machine_configuration()
      ->mutable_cpu_svn()
      ->set_value(kValidCpuSvn);

  SgxIdentity identity = expectation.reference_identity();
  identity.mutable_machine_configuration()->mutable_cpu_svn()->set_value(
      kValidCpuSvn2);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("does not match expected CPUSVN value"));
}

// Check that an SgxIdentity does not match an expectation with a differing
// SGX Type when SGX Type match is required.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentitySgxTypeMismatch) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));

  // Require a match on SGX type.
  expectation.mutable_match_spec()
      ->mutable_machine_configuration_match_spec()
      ->set_is_sgx_type_match_required(true);
  expectation.mutable_reference_identity()
      ->mutable_machine_configuration()
      ->set_sgx_type(SgxType::STANDARD);

  SgxIdentity identity = expectation.reference_identity();
  identity.mutable_machine_configuration()->set_sgx_type(
      SgxType::SGX_TYPE_UNKNOWN);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("does not match expected SGX Type"));
}

// Make sure that enclave identity match fails with appropriate status if the
// target expectation is invalid.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityMatchInvalidExpectation) {
  SgxIdentity identity =
      GetMinimalValidSgxIdentity(kLongAll5, attributes_all_5_);
  *identity.mutable_code_identity()->mutable_mrenclave() = h_acedface_;
  *identity.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentityExpectation expectation;
  EXPECT_THAT(MatchIdentityToExpectation(identity, expectation,
                                         /*explanation=*/nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Expectation parameter is invalid"));
}

// Make sure that enclave identity match fails with appropriate status if the
// target identity is invalid.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityMatchInvalidIdentity) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAllF, attributes_all_f_));

  EXPECT_THAT(MatchIdentityToExpectation(SgxIdentity::default_instance(),
                                         expectation, /*explanation=*/nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Identity parameter is invalid"));
}

// Make sure that enclave identity match fails with appropriate status if
// match_spec.mrenclave_match_required is true, but the target identity is
// missing mrenclave.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityMatchIdentityMissingMrenclave) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAllF, attributes_all_f_));
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrenclave_match_required(true);
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_mrenclave() = h_acedface_;

  SgxIdentity identity = expectation.reference_identity();
  identity.mutable_code_identity()->clear_mrenclave();

  EXPECT_THAT(MatchIdentityToExpectation(identity, expectation,
                                         /*explanation=*/nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Identity is not compatible with specified match spec"));
}

// Make sure that enclave identity match fails with appropriate status if
// match_spec.mrsigner is true, but the target identity is missing mrsigner.
TEST_F(SgxIdentityUtilInternalTest, SgxIdentityMatchIdentityMissingMrsigner) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAllF, attributes_all_f_));
  expectation.mutable_match_spec()
      ->mutable_code_identity_match_spec()
      ->set_is_mrsigner_match_required(true);
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, 0, 0);

  SgxIdentity identity = expectation.reference_identity();
  identity.mutable_code_identity()
      ->mutable_signer_assigned_identity()
      ->clear_mrsigner();

  EXPECT_THAT(MatchIdentityToExpectation(identity, expectation,
                                         /*explanation=*/nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Identity is not compatible with specified match spec"));
}

TEST_F(SgxIdentityUtilInternalTest,
       CodeIdentityMatchMultipleMismatchedProperties) {
  SgxIdentityExpectation expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expectation, GetMinimalValidSgxExpectation(kLongAll5, attributes_all_5_));
  *expectation.mutable_match_spec() = GetMinimalValidSgxMatchSpec();
  *expectation.mutable_reference_identity()
       ->mutable_code_identity()
       ->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, /*isvprodid=*/0, /*isvsvn=*/0);

  // Require a match on CPUSVN.
  expectation.mutable_match_spec()
      ->mutable_machine_configuration_match_spec()
      ->set_is_cpu_svn_match_required(true);
  expectation.mutable_reference_identity()
      ->mutable_machine_configuration()
      ->mutable_cpu_svn()
      ->set_value(kValidCpuSvn);

  // The CPUSVN and ISVPRODID values are mismatched.
  SgxIdentity identity = expectation.reference_identity();
  identity.mutable_machine_configuration()->mutable_cpu_svn()->set_value(
      kValidCpuSvn2);
  *identity.mutable_code_identity()->mutable_signer_assigned_identity() =
      MakeSignerAssignedIdentity(h_acedface_, /*isvprodid=*/1, /*isvsvn=*/0);

  std::string explanation;
  ASSERT_THAT(MatchIdentityToExpectation(identity, expectation, &explanation),
              IsOkAndHolds(false));
  EXPECT_THAT(explanation, HasSubstr("does not match expected CPUSVN value"));
  EXPECT_THAT(explanation,
              HasSubstr("does not match expected ISVPRODID value"));
  EXPECT_THAT(explanation, HasSubstr("and"));
}

TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentityFromHardwareReport) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr reportdata;

  *tinfo = TrivialZeroObject<Targetinfo>();
  *reportdata = TrivialZeroObject<Reportdata>();

  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, hardware_->GetReport(*tinfo, *reportdata));
  SgxIdentity identity = ParseSgxIdentityFromHardwareReport(report.body);
  CodeIdentity code_identity = identity.code_identity();
  EXPECT_TRUE(std::equal(
      report.body.mrenclave.cbegin(), report.body.mrenclave.cend(),
      code_identity.mrenclave().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_TRUE(std::equal(
      report.body.mrsigner.cbegin(), report.body.mrsigner.cend(),
      code_identity.signer_assigned_identity().mrsigner().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_EQ(report.body.isvprodid,
            code_identity.signer_assigned_identity().isvprodid());
  EXPECT_EQ(report.body.isvsvn,
            code_identity.signer_assigned_identity().isvsvn());

  SecsAttributeSet attributes(code_identity.attributes());
  EXPECT_EQ(report.body.attributes, attributes);
  EXPECT_EQ(report.body.miscselect, code_identity.miscselect());

  CpuSvn report_cpusvn;
  report_cpusvn.set_value(report.body.cpusvn.data(), report.body.cpusvn.size());
  EXPECT_THAT(identity.machine_configuration().cpu_svn(),
              EqualsProto(report_cpusvn));
}

TEST_F(SgxIdentityUtilInternalTest, SetDefaultLocalSgxMatchSpec) {
  SgxIdentityMatchSpec spec;
  SetDefaultLocalSgxMatchSpec(&spec);
  EXPECT_FALSE(spec.code_identity_match_spec().is_mrenclave_match_required());
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrsigner_match_required());
  EXPECT_EQ(spec.code_identity_match_spec().miscselect_match_mask(), kLongAllF);
  SecsAttributeSet attributes = SecsAttributeSet::GetDefaultDoNotCareBits();

  EXPECT_EQ(spec.code_identity_match_spec().attributes_match_mask(),
            (~attributes).ToProtoAttributes());

  EXPECT_FALSE(
      spec.machine_configuration_match_spec().is_cpu_svn_match_required());
}

TEST_F(SgxIdentityUtilInternalTest, SetStrictLocalSgxMatchSpec) {
  SgxIdentityMatchSpec spec;
  SetStrictLocalSgxMatchSpec(&spec);
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrenclave_match_required());
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrsigner_match_required());
  EXPECT_EQ(spec.code_identity_match_spec().miscselect_match_mask(), kLongAllF);
  EXPECT_EQ(spec.code_identity_match_spec().attributes_match_mask(),
            SecsAttributeSet::GetStrictMask().ToProtoAttributes());

  EXPECT_TRUE(
      spec.machine_configuration_match_spec().is_cpu_svn_match_required());
  EXPECT_FALSE(
      spec.machine_configuration_match_spec().is_sgx_type_match_required());
}

TEST_F(SgxIdentityUtilInternalTest, SetDefaultRemoteSgxMatchSpec) {
  SgxIdentityMatchSpec spec;
  SetDefaultRemoteSgxMatchSpec(&spec);
  EXPECT_FALSE(spec.code_identity_match_spec().is_mrenclave_match_required());
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrsigner_match_required());
  EXPECT_EQ(spec.code_identity_match_spec().miscselect_match_mask(), kLongAllF);
  SecsAttributeSet attributes = SecsAttributeSet::GetDefaultDoNotCareBits();

  EXPECT_EQ(spec.code_identity_match_spec().attributes_match_mask(),
            (~attributes).ToProtoAttributes());

  EXPECT_FALSE(
      spec.machine_configuration_match_spec().is_cpu_svn_match_required());
  EXPECT_FALSE(
      spec.machine_configuration_match_spec().is_sgx_type_match_required());
}

TEST_F(SgxIdentityUtilInternalTest, SetStrictRemoteSgxMatchSpec) {
  SgxIdentityMatchSpec spec;
  SetStrictRemoteSgxMatchSpec(&spec);
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrenclave_match_required());
  EXPECT_TRUE(spec.code_identity_match_spec().is_mrsigner_match_required());
  EXPECT_EQ(spec.code_identity_match_spec().miscselect_match_mask(), kLongAllF);
  EXPECT_EQ(spec.code_identity_match_spec().attributes_match_mask(),
            SecsAttributeSet::GetStrictMask().ToProtoAttributes());

  EXPECT_TRUE(
      spec.machine_configuration_match_spec().is_cpu_svn_match_required());
  EXPECT_TRUE(
      spec.machine_configuration_match_spec().is_sgx_type_match_required());
}

TEST_F(SgxIdentityUtilInternalTest, SetSelfSgxIdentity) {
  SgxIdentity identity;
  SetSelfSgxIdentity(&identity);
  EXPECT_TRUE(std::equal(
      enclave_->get_mrenclave().cbegin(), enclave_->get_mrenclave().cend(),
      identity.code_identity().mrenclave().hash().cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_TRUE(std::equal(
      enclave_->get_mrsigner().cbegin(), enclave_->get_mrsigner().cend(),
      identity.code_identity()
          .signer_assigned_identity()
          .mrsigner()
          .hash()
          .cbegin(),
      // Cast char to unsigned char before checking for equality.
      [](const uint8_t a, const unsigned char b) { return a == b; }));
  EXPECT_EQ(enclave_->get_isvprodid(),
            identity.code_identity().signer_assigned_identity().isvprodid());
  EXPECT_EQ(enclave_->get_isvsvn(),
            identity.code_identity().signer_assigned_identity().isvsvn());

  SecsAttributeSet attributes(identity.code_identity().attributes());
  EXPECT_EQ(enclave_->get_attributes(), attributes);
  EXPECT_EQ(enclave_->get_miscselect(), identity.code_identity().miscselect());

  UnsafeBytes<kCpusvnSize> cpu_svn;
  ASYLO_ASSERT_OK(SetTrivialObjectFromBinaryString<UnsafeBytes<kCpusvnSize>>(
      identity.machine_configuration().cpu_svn().value(), &cpu_svn));
  EXPECT_EQ(enclave_->get_cpusvn(), cpu_svn);
}

TEST_F(SgxIdentityUtilInternalTest, SetDefaultLocalSelfSgxExpectation) {
  SgxIdentity identity;
  SetSelfSgxIdentity(&identity);

  SgxIdentityMatchSpec match_spec;
  SetDefaultLocalSgxMatchSpec(&match_spec);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetDefaultLocalSelfSgxExpectation(&expectation));

  EXPECT_THAT(expectation.reference_identity(), EqualsProto(identity))
      << FormatProto(expectation.reference_identity()) << FormatProto(identity);
  EXPECT_THAT(expectation.match_spec(), EqualsProto(match_spec))
      << FormatProto(expectation.match_spec()) << FormatProto(match_spec);
}

TEST_F(SgxIdentityUtilInternalTest, SetStrictLocalSelfSgxExpectation) {
  SgxIdentity identity;
  SetSelfSgxIdentity(&identity);

  SgxIdentityMatchSpec match_spec;
  SetStrictLocalSgxMatchSpec(&match_spec);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetStrictLocalSelfSgxExpectation(&expectation));

  EXPECT_THAT(expectation.reference_identity(), EqualsProto(identity))
      << FormatProto(expectation.reference_identity()) << FormatProto(identity);
  EXPECT_THAT(expectation.match_spec(), EqualsProto(match_spec))
      << FormatProto(expectation.match_spec()) << FormatProto(match_spec);
}

TEST_F(SgxIdentityUtilInternalTest, SetDefaultRemoteSelfSgxExpectation) {
  SgxIdentity identity;
  SetSelfSgxIdentity(&identity);

  SgxIdentityMatchSpec match_spec;
  SetDefaultRemoteSgxMatchSpec(&match_spec);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetDefaultRemoteSelfSgxExpectation(&expectation));

  EXPECT_THAT(expectation.reference_identity(), EqualsProto(identity))
      << FormatProto(expectation.reference_identity()) << FormatProto(identity);
  EXPECT_THAT(expectation.match_spec(), EqualsProto(match_spec))
      << FormatProto(expectation.match_spec()) << FormatProto(match_spec);
}

TEST_F(SgxIdentityUtilInternalTest, SetStrictRemoteSelfSgxExpectation) {
  SgxIdentity identity;
  SetSelfSgxIdentity(&identity);

  SgxIdentityMatchSpec match_spec;
  SetStrictRemoteSgxMatchSpec(&match_spec);

  SgxIdentityExpectation expectation;
  ASYLO_EXPECT_OK(SetStrictRemoteSelfSgxExpectation(&expectation));

  EXPECT_THAT(expectation.reference_identity(), EqualsProto(identity))
      << FormatProto(expectation.reference_identity()) << FormatProto(identity);
  EXPECT_THAT(expectation.match_spec(), EqualsProto(match_spec))
      << FormatProto(expectation.match_spec()) << FormatProto(match_spec);
}

TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentitySuccess) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    SgxIdentity generated_sgx_identity;
    ASYLO_ASSERT_OK(SetRandomValidGenericIdentity(&generic_identity,
                                                  &generated_sgx_identity));
    SgxIdentity parsed_sgx_identity;
    ASYLO_ASSERT_OK(ParseSgxIdentity(generic_identity, &parsed_sgx_identity));
    ASSERT_THAT(generated_sgx_identity, EquivalentProto(parsed_sgx_identity))
        << FormatProto(generated_sgx_identity)
        << FormatProto(parsed_sgx_identity);
  }
}

// Parse SgxIdentity-based EnclaveIdentity messages into SgxIdentity.
TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentityFailure) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentity generic_identity;
    ASYLO_ASSERT_OK(SetRandomInvalidGenericIdentity(&generic_identity));
    SgxIdentity parsed_sgx_identity;
    ASSERT_THAT(ParseSgxIdentity(generic_identity, &parsed_sgx_identity),
                Not(IsOk()));
  }
}

TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentityMatchSpecSuccess) {
  std::string generic_match_spec;
  SgxIdentityMatchSpec generated_sgx_spec;
  SgxIdentityMatchSpec parsed_sgx_spec;

  for (int i = 0; i < kNumRandomParseTrials; i++) {
    ASYLO_ASSERT_OK(SetRandomValidGenericMatchSpec(&generic_match_spec,
                                                   &generated_sgx_spec));
    ASYLO_ASSERT_OK(ParseSgxMatchSpec(generic_match_spec, &parsed_sgx_spec));

    ASSERT_THAT(generated_sgx_spec, EquivalentProto(parsed_sgx_spec))
        << FormatProto(parsed_sgx_spec) << FormatProto(generated_sgx_spec);
  }
}

TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentityMatchSpecFailure) {
  std::string generic_match_spec;
  SgxIdentityMatchSpec parsed_sgx_spec;

  for (int i = 0; i < kNumRandomParseTrials; i++) {
    ASYLO_ASSERT_OK(SetRandomInvalidGenericMatchSpec(&generic_match_spec));
    ASSERT_THAT(ParseSgxMatchSpec(generic_match_spec, &parsed_sgx_spec),
                Not(IsOk()));
  }
  generic_match_spec = kInvalidString;
  EXPECT_THAT(ParseSgxMatchSpec(generic_match_spec, &parsed_sgx_spec),
              Not(IsOk()));
}

TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentityExpectationSuccess) {
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

TEST_F(SgxIdentityUtilInternalTest, ParseSgxIdentityExpectationFailure) {
  for (int i = 0; i < kNumRandomParseTrials; i++) {
    EnclaveIdentityExpectation generic_expectation;

    ASYLO_ASSERT_OK(SetRandomInvalidGenericExpectation(&generic_expectation));
    SgxIdentityExpectation parsed_sgx_expectation;
    ASSERT_THAT(
        ParseSgxExpectation(generic_expectation, &parsed_sgx_expectation),
        Not(IsOk()));
  }
}

TEST_F(SgxIdentityUtilInternalTest, SerializeAndParseSgxIdentityEndToEnd) {
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

TEST_F(SgxIdentityUtilInternalTest,
       SerializeAndParseSgxIdentityMatchSpecEndToEnd) {
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

TEST_F(SgxIdentityUtilInternalTest,
       SerializeAndParseSgxIdentityExpectationEndToEnd) {
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

TEST_F(SgxIdentityUtilInternalTest, SetTargetinfoFromSelfIdentity) {
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

TEST_F(SgxIdentityUtilInternalTest, VerifyHardwareReportPositive) {
  AlignedTargetinfoPtr tinfo;
  SetTargetinfoFromSelfIdentity(tinfo.get());

  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, hardware_->GetReport(*tinfo, *data));
  ASYLO_EXPECT_OK(VerifyHardwareReport(report));
}

TEST_F(SgxIdentityUtilInternalTest,
       VerifyHardwareReportWrongTargetMeasurement) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();

  SetTargetinfoFromSelfIdentity(tinfo.get());
  tinfo->measurement[0] ^= 0xFFFF;
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, hardware_->GetReport(*tinfo, *data));
  EXPECT_THAT(VerifyHardwareReport(report), Not(IsOk()));
}

TEST_F(SgxIdentityUtilInternalTest, VerifyHardwareReportWrongTargetAttributes) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();

  SetTargetinfoFromSelfIdentity(tinfo.get());
  Attributes attributes = tinfo->attributes.ToProtoAttributes();
  tinfo->attributes = SecsAttributeSet(
      attributes.flags() ^ std::numeric_limits<uint64_t>::max(),
      attributes.xfrm() ^ std::numeric_limits<uint64_t>::max());
  tinfo->attributes &= SecsAttributeSet::GetAllSupportedBits();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, hardware_->GetReport(*tinfo, *data));
  EXPECT_THAT(VerifyHardwareReport(report), Not(IsOk()));
}

TEST_F(SgxIdentityUtilInternalTest, VerifyHardwareReportWrongTargetMiscSelect) {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();

  SetTargetinfoFromSelfIdentity(tinfo.get());
  tinfo->miscselect ^= std::numeric_limits<uint32_t>::max();
  tinfo->miscselect &= kValidMiscselectBitmask;
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, hardware_->GetReport(*tinfo, *data));
  EXPECT_THAT(VerifyHardwareReport(report), Not(IsOk()));
}

TEST_F(SgxIdentityUtilInternalTest, VerifyHardwareReportBadReport) {
  AlignedTargetinfoPtr tinfo;
  SetTargetinfoFromSelfIdentity(tinfo.get());

  AlignedReportdataPtr data;
  *data = TrivialRandomObject<Reportdata>();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report, hardware_->GetReport(*tinfo, *data));
  // Corrupt the REPORT by flipping the first byte of MRENCLAVE.
  report.body.mrenclave[0] ^= 0xFFFF;
  EXPECT_THAT(VerifyHardwareReport(report), Not(IsOk()));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
