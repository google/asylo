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

#include "asylo/identity/platform/sgx/internal/secs_attributes.h"

#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

constexpr uint64_t kLongLongAllF = 0xFFFFFFFFFFFFFFFFULL;

// A test fixture is used to ensure naming consistency, maintaining common
// set of constants, and future extensibility.
class SecsAttributesTest : public ::testing::Test {
 protected:
  SecsAttributesTest() {}

  // Independently define all the attribute bits so that any error
  // introduced in this part of the header file is caught.
  const std::vector<AttributeBit> attributes_ = {
      static_cast<AttributeBit>(0),  // FLAG_ATTRIBUTE_INIT
      static_cast<AttributeBit>(1),  // FLAG_ATTRIBUTE_DEBUG
      static_cast<AttributeBit>(2),  // FLAG_ATTRIBUTE_MODE64BIT
                                     // Unused bit
      static_cast<AttributeBit>(4),  // FLAG_ATTRIBUTE_PROVISIONKEY
      static_cast<AttributeBit>(5),  // FLAG_ATTRIBUTE_INITTOKENKEY
                                     // Unused bit
      static_cast<AttributeBit>(7),  // FLAG_ATTRIBUTE_KSS

      static_cast<AttributeBit>(64),  // XFRM_ATTRIBUTE_FPU,
      static_cast<AttributeBit>(65),  // XFRM_ATTRIBUTE_SSE,
      static_cast<AttributeBit>(66),  // XFRM_ATTRIBUTE_AVX,
      static_cast<AttributeBit>(67),  // XFRM_ATTRIBUTE_BNDREG,
      static_cast<AttributeBit>(68),  // XFRM_ATTRIBUTE_BNDCSR,
      static_cast<AttributeBit>(69),  // XFRM_ATTRIBUTE_OPMASK,
      static_cast<AttributeBit>(70),  // XFRM_ATTRIBUTE_ZMM_HI256,
      static_cast<AttributeBit>(71),  // XFRM_ATTRIBUTE_HI16_ZMM,
                                      // Unused bit
      static_cast<AttributeBit>(73)   // XFRM_ATTRIBUTE_PKRU
  };
  const std::vector<SecsAttributeSet> attribute_sets_ = {
      {0x1, 0x0},   // INIT
      {0x2, 0x0},   // DEBUG
      {0x4, 0x0},   // MODE64BIT
      {0x10, 0x0},  // PROVISIONKEY
      {0x20, 0x0},  // INITTOKENKEY
      {0x80, 0x0},  // KSS

      {0x0, 0x1},    // FPU
      {0x0, 0x2},    // SSE
      {0x0, 0x4},    // AVX
      {0x0, 0x8},    // BNDREG
      {0x0, 0x10},   // BNDCSR
      {0x0, 0x20},   // OPMASK
      {0x0, 0x40},   // ZMM_HI256
      {0x0, 0x80},   // HI16_ZMM
      {0x0, 0x200},  // PKRU
  };
  const SecsAttributeSet all_attributes_ = {0xb7, 0x2FF};
  const AttributeBit bad_attribute_ = static_cast<AttributeBit>(129);
};

#define EXPECT_LOG(TYPE, MESSAGE)

// Verify the correctness of ClearSecsAttributeSet.
TEST_F(SecsAttributesTest, ClearSecsAttributeSet) {
  for (SecsAttributeSet set : attribute_sets_) {
    set.Clear();
    EXPECT_EQ(set.flags, 0);
    EXPECT_EQ(set.xfrm, 0);
  }

  SecsAttributeSet set;
  set = all_attributes_;
  set.Clear();
  EXPECT_EQ(set.flags, 0);
  EXPECT_EQ(set.xfrm, 0);
}

// Verify the correctness of the equality operator.
TEST_F(SecsAttributesTest, Equality) {
  for (int i = 0; i < attributes_.size(); i++) {
    for (int j = 0; j < attributes_.size(); j++) {
      EXPECT_EQ((attributes_[i] == attributes_[j]), (i == j));
    }
  }
}

// Verify the correctness of the inequality operator.
TEST_F(SecsAttributesTest, Inequality) {
  for (int i = 0; i < attributes_.size(); i++) {
    for (int j = 0; j < attributes_.size(); j++) {
      EXPECT_EQ((attributes_[i] != attributes_[j]), (i != j));
    }
  }
}

// Verify the correctness of the bitwise OR operator.
TEST_F(SecsAttributesTest, BitwiseOr) {
  SecsAttributeSet result = TrivialZeroObject<SecsAttributeSet>();

  // Verify that ORing an attribute set with itself does not change the set.
  for (const SecsAttributeSet &set : attribute_sets_) {
    result = set | set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }

  // Verify that attribute accumulation via ORing works correctly.
  result = TrivialZeroObject<SecsAttributeSet>();
  for (const SecsAttributeSet &set : attribute_sets_) {
    result = result | set;
  }
  EXPECT_EQ(result.flags, all_attributes_.flags);
  EXPECT_EQ(result.xfrm, all_attributes_.xfrm);

  // Verify that ORing an attribute set with all zeros does not change the set.
  result = result | TrivialZeroObject<SecsAttributeSet>();
  EXPECT_EQ(result.flags, all_attributes_.flags);
  EXPECT_EQ(result.xfrm, all_attributes_.xfrm);
}

// Verify the correctness of the bitwise OR-assign operator.
TEST_F(SecsAttributesTest, BitwiseOrAssign) {
  SecsAttributeSet result = TrivialZeroObject<SecsAttributeSet>();

  // Verify that ORing an attribute set with itself does not change the set.
  for (const SecsAttributeSet &set : attribute_sets_) {
    result = set;
    result |= set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }

  // Verify that attribute accumulation via ORing works correctly.
  result = TrivialZeroObject<SecsAttributeSet>();
  for (const SecsAttributeSet &set : attribute_sets_) {
    result |= set;
  }
  EXPECT_EQ(result.flags, all_attributes_.flags);
  EXPECT_EQ(result.xfrm, all_attributes_.xfrm);

  // Verify that ORing an attribute set with all zeros does not change the set.
  result |= TrivialZeroObject<SecsAttributeSet>();
  EXPECT_EQ(result.flags, all_attributes_.flags);
  EXPECT_EQ(result.xfrm, all_attributes_.xfrm);
}

// Verify the correctness of the bitwise AND operator.
TEST_F(SecsAttributesTest, BitwiseAnd) {
  // Verify that ANDing a single-bit attribute set with an attribute set that
  // has all the attributes lit yields correct result.
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = all_attributes_ & set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }

  // Verify that ANDing an attribute set with all zeros yields an attribute set
  // with all zeros.
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = TrivialZeroObject<SecsAttributeSet>() & set;
    EXPECT_EQ(result.flags, 0);
    EXPECT_EQ(result.xfrm, 0);
  }
}

// Verify the correctness of the bitwise AND-assign operator.
TEST_F(SecsAttributesTest, BitwiseAndAssign) {
  // Verify that ANDing a single-bit attribute set with an attribute set that
  // has all the attributes lit yields correct result.
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = all_attributes_;
    result &= set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }

  // Verify that ANDing an attribute set with all zeros yields an attribute set
  // with all zeros.
  SecsAttributeSet result = TrivialZeroObject<SecsAttributeSet>();
  for (const SecsAttributeSet &set : attribute_sets_) {
    result &= set;
    EXPECT_EQ(result.flags, 0);
    EXPECT_EQ(result.xfrm, 0);
  }
}

// Verify the correctness of the bitwise XOR operator.
TEST_F(SecsAttributesTest, BitwiseXor) {
  // Verify that XORing a set with itself results in all zeroes.
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = set ^ set;
    EXPECT_EQ(result.flags, 0);
    EXPECT_EQ(result.xfrm, 0);
  }

  // Verify that XORing a set with all zeroes results in the same set.
  SecsAttributeSet all_zeroes = TrivialZeroObject<SecsAttributeSet>();
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = all_zeroes ^ set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }
}

// Verify the correctness of the bitwise XOR-assign operator.
TEST_F(SecsAttributesTest, BitwiseXorAssign) {
  // Verify that XORing a set with itself results in all zeroes.
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = set;
    result ^= set;
    EXPECT_EQ(result.flags, 0);
    EXPECT_EQ(result.xfrm, 0);
  }

  // Verify that XORing a set with all zeroes results in the same set.
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = TrivialZeroObject<SecsAttributeSet>();
    result ^= set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }
}

// Verify the correctness of the bitwise negation operator.
TEST_F(SecsAttributesTest, BitwiseNegation) {
  SecsAttributeSet zeros = TrivialZeroObject<SecsAttributeSet>();
  SecsAttributeSet ones = TrivialOnesObject<SecsAttributeSet>();

  for (const SecsAttributeSet &set : attribute_sets_) {
    EXPECT_EQ(set & ~set, zeros);
    EXPECT_EQ(set | ~set, ones);
  }
}

// Verify the correctness of conversion from attribute list to attribute set.
TEST_F(SecsAttributesTest, ListToSet) {
  for (int i = 0; i < attributes_.size(); i++) {
    std::vector<AttributeBit> v{attributes_[i]};

    SecsAttributeSet set;
    ASYLO_ASSERT_OK_AND_ASSIGN(set, SecsAttributeSet::FromBits(v));
    EXPECT_EQ(set.flags, attribute_sets_[i].flags);
    EXPECT_EQ(set.xfrm, attribute_sets_[i].xfrm);
  }

  SecsAttributeSet set;
  ASYLO_ASSERT_OK_AND_ASSIGN(set, SecsAttributeSet::FromBits(attributes_));
  EXPECT_EQ(set.flags, all_attributes_.flags);
  EXPECT_EQ(set.xfrm, all_attributes_.xfrm);
}

// Verify error condition for conversion from attribute list to attribute set.
TEST_F(SecsAttributesTest, ListToSetError) {
  std::vector<AttributeBit> v{bad_attribute_};
  std::string str =
      absl::StrCat("SecsAttributeBit specifies a bit position ",
                   static_cast<size_t>(bad_attribute_),
                   " that is larger than the max allowed value of 127");
  EXPECT_LOG(ERROR, str);
  EXPECT_THAT(SecsAttributeSet::FromBits(v),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify the correctness of conversion from AttributeSet to Attributes.
TEST_F(SecsAttributesTest, SetToAttributes) {
  for (int i = 0; i < attribute_sets_.size(); i++) {
    Attributes attributes = attribute_sets_[i].ToProtoAttributes();
    EXPECT_EQ(attributes.flags(), attribute_sets_[i].flags);
    EXPECT_EQ(attributes.xfrm(), attribute_sets_[i].xfrm);
  }
}

// Verify the correctness of conversion from Attributes to AttributeSet.
TEST_F(SecsAttributesTest, AttributesToSet) {
  std::vector<AttributeBit> list;
  Attributes attributes;

  for (int i = 0; i < attribute_sets_.size(); i++) {
    attributes.set_flags(attribute_sets_[i].flags);
    attributes.set_xfrm(attribute_sets_[i].xfrm);
    SecsAttributeSet attribute_set(attributes);
    EXPECT_EQ(attributes.flags(), attribute_set.flags);
    EXPECT_EQ(attributes.xfrm(), attribute_set.xfrm);
  }

  attributes.set_flags(all_attributes_.flags);
  attributes.set_xfrm(all_attributes_.xfrm);
  SecsAttributeSet attribute_set(attributes);
  EXPECT_EQ(attributes.flags(), all_attributes_.flags);
  EXPECT_EQ(attributes.xfrm(), all_attributes_.xfrm);
}

// Verify the correctness of IsSet on a set.
TEST_F(SecsAttributesTest, TestAttributeSet) {
  for (int i = 0; i < attribute_sets_.size(); i++) {
    for (int j = 0; j < attributes_.size(); j++) {
      EXPECT_EQ(attribute_sets_[i].IsSet(attributes_[j]), (i == j));
    }
  }
  for (int j = 0; j < attributes_.size(); j++) {
    EXPECT_TRUE(all_attributes_.IsSet(attributes_[j]));
  }
}

// Verify the error-handling in TestAttribute on a set.
TEST_F(SecsAttributesTest, TestAttributeSetError) {
  std::string str =
      absl::StrCat("SecsAttributeBit specifies a bit position ",
                   static_cast<size_t>(bad_attribute_),
                   " that is larger than the max allowed value of 127");

  EXPECT_LOG(ERROR, str);

  EXPECT_FALSE(all_attributes_.IsSet(bad_attribute_));
}

// Verify that SecsAttributeSet::FromBits fails for an invalid attribute bit.
TEST_F(SecsAttributesTest, FromBitsNegative) {
  EXPECT_THAT(SecsAttributeSet::FromBits({bad_attribute_}),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that SetDefaultSecsAttributesMask creates a mask that is the logical
// NOT of the "do not care" attributes set.
TEST_F(SecsAttributesTest, SetDefaultSecsAttributesMask) {
  SecsAttributeSet attributes_match_mask = SecsAttributeSet::GetDefaultMask();
  SecsAttributeSet do_not_care_attributes =
      SecsAttributeSet::GetDefaultDoNotCareBits();

  EXPECT_EQ(~attributes_match_mask.flags, do_not_care_attributes.flags);
  EXPECT_EQ(~attributes_match_mask.xfrm, do_not_care_attributes.xfrm);
}

// Verify that SecsAttributeSet::GetStrictMask creates a mask that sets all
// possible attributes bits.
TEST_F(SecsAttributesTest, GetStrictMask) {
  Attributes attributes_match_mask =
      SecsAttributeSet::GetStrictMask().ToProtoAttributes();

  EXPECT_EQ(attributes_match_mask.flags(), kLongLongAllF);
  EXPECT_EQ(attributes_match_mask.xfrm(), kLongLongAllF);
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
