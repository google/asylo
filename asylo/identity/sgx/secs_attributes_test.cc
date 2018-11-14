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

#include "asylo/identity/sgx/secs_attributes.h"

#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/attributes.pb.h"
#include "asylo/test/util/status_matchers.h"

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
  const std::vector<SecsAttributeBit> attributes_ = {
      static_cast<SecsAttributeBit>(0),  // FLAG_ATTRIBUTE_INIT
      static_cast<SecsAttributeBit>(1),  // FLAG_ATTRIBUTE_DEBUG
      static_cast<SecsAttributeBit>(2),  // FLAG_ATTRIBUTE_MODE64BIT
                                         // Unused bit
      static_cast<SecsAttributeBit>(4),  // FLAG_ATTRIBUTE_PROVISIONKEY
      static_cast<SecsAttributeBit>(5),  // FLAG_ATTRIBUTE_INITTOKENKEY
                                         // Unused bit
      static_cast<SecsAttributeBit>(7),  // FLAG_ATTRIBUTE_KSS

      static_cast<SecsAttributeBit>(64),  // XFRM_ATTRIBUTE_FPU,
      static_cast<SecsAttributeBit>(65),  // XFRM_ATTRIBUTE_SSE,
      static_cast<SecsAttributeBit>(66),  // XFRM_ATTRIBUTE_AVX,
      static_cast<SecsAttributeBit>(67),  // XFRM_ATTRIBUTE_BNDREG,
      static_cast<SecsAttributeBit>(68),  // XFRM_ATTRIBUTE_BNDCSR,
      static_cast<SecsAttributeBit>(69),  // XFRM_ATTRIBUTE_OPMASK,
      static_cast<SecsAttributeBit>(70),  // XFRM_ATTRIBUTE_ZMM_HI256,
      static_cast<SecsAttributeBit>(71),  // XFRM_ATTRIBUTE_HI16_ZMM,
                                          // Unused bit
      static_cast<SecsAttributeBit>(73)   // XFRM_ATTRIBUTE_PKRU
  };
  const std::vector<std::string> attribute_names_ = {
      "INIT",   "DEBUG",  "MODE64BIT", "PROVISIONKEY", "INITTOKENKEY",
      "KSS",    "FPU",    "SSE",       "AVX",          "BNDREG",
      "BNDCSR", "OPMASK", "ZMM_HI256", "HI16_ZMM",     "PKRU"};
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
  const SecsAttributeBit bad_attribute_ = static_cast<SecsAttributeBit>(129);
};

#define EXPECT_LOG(TYPE, MESSAGE)
#if 0
#define EXPECT_LOG(TYPE, MESSAGE)                                            \
  EXPECT_CALL(mock_log_, Log(TYPE, ::testing::_, ::testing::StrEq(MESSAGE))) \
      .Times(1)
#endif

// Verify the correctness of ClearSecsAttributeSet.
TEST_F(SecsAttributesTest, ClearSecsAttributeSet) {
  for (SecsAttributeSet set : attribute_sets_) {
    ClearSecsAttributeSet(&set);
    EXPECT_EQ(set.flags, 0);
    EXPECT_EQ(set.xfrm, 0);
  }

  SecsAttributeSet set;
  set = all_attributes_;
  ClearSecsAttributeSet(&set);
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

// Verify the correctness of bit-wise OR operator.
TEST_F(SecsAttributesTest, BitwiseOr) {
  SecsAttributeSet result;

  for (const SecsAttributeSet &set : attribute_sets_) {
    result = set | set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }

  result = TrivialZeroObject<SecsAttributeSet>();
  for (const SecsAttributeSet &set : attribute_sets_) {
    result = result | set;
  }
  EXPECT_EQ(result.flags, all_attributes_.flags);
  EXPECT_EQ(result.xfrm, all_attributes_.xfrm);

  SecsAttributeSet cleared_set = TrivialZeroObject<SecsAttributeSet>();
  result = result | cleared_set;
  EXPECT_EQ(result.flags, all_attributes_.flags);
  EXPECT_EQ(result.xfrm, all_attributes_.xfrm);
}

// Verify the correctness of bit-wise AND operator.
TEST_F(SecsAttributesTest, BitwiseAnd) {
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = all_attributes_ & set;
    EXPECT_EQ(result.flags, set.flags);
    EXPECT_EQ(result.xfrm, set.xfrm);
  }

  SecsAttributeSet cleared_set = TrivialZeroObject<SecsAttributeSet>();
  for (const SecsAttributeSet &set : attribute_sets_) {
    SecsAttributeSet result = cleared_set & set;
    EXPECT_EQ(result.flags, 0);
    EXPECT_EQ(result.xfrm, 0);
  }
}

// Verify the correctness of bit-wise negation operator.
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
    std::vector<SecsAttributeBit> v{attributes_[i]};

    SecsAttributeSet set;
    EXPECT_TRUE(ConvertSecsAttributeRepresentation(v, &set));
    EXPECT_EQ(set.flags, attribute_sets_[i].flags);
    EXPECT_EQ(set.xfrm, attribute_sets_[i].xfrm);
  }

  SecsAttributeSet set;
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes_, &set));
  EXPECT_EQ(set.flags, all_attributes_.flags);
  EXPECT_EQ(set.xfrm, all_attributes_.xfrm);
}

// Verify error condition for conversion from attribute list to attribute set.
TEST_F(SecsAttributesTest, ListToSetError) {
  std::vector<SecsAttributeBit> v{bad_attribute_};
  std::string str =
      absl::StrCat("SecsAttributeBit specifies a bit position ",
                   static_cast<size_t>(bad_attribute_),
                   " that is larger than the max allowed value of 127");
  EXPECT_LOG(ERROR, str);
  SecsAttributeSet set;
  EXPECT_FALSE(ConvertSecsAttributeRepresentation(v, &set));
}

// Verify the correctness of conversion from AttributeSet to attribute list.
TEST_F(SecsAttributesTest, SetToList) {
  std::vector<SecsAttributeBit> list;
  for (int i = 0; i < attribute_sets_.size(); i++) {
    EXPECT_TRUE(ConvertSecsAttributeRepresentation(attribute_sets_[i], &list));
    EXPECT_EQ(list.size(), 1);
    EXPECT_EQ(list[0], attributes_[i]);
  }

  EXPECT_TRUE(ConvertSecsAttributeRepresentation(all_attributes_, &list));
  EXPECT_EQ(list.size(), attributes_.size());
  for (int i = 0; i < list.size(); i++) {
    EXPECT_EQ(list[i], attributes_[i]);
  }
}

// Verify the correctness of conversion from attribute list to Attributes.
TEST_F(SecsAttributesTest, ListToAttributes) {
  for (int i = 0; i < attributes_.size(); i++) {
    std::vector<SecsAttributeBit> v{attributes_[i]};

    Attributes attributes;
    EXPECT_TRUE(ConvertSecsAttributeRepresentation(v, &attributes));
    EXPECT_EQ(attributes.flags(), attribute_sets_[i].flags);
    EXPECT_EQ(attributes.xfrm(), attribute_sets_[i].xfrm);
  }

  Attributes attributes;
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(all_attributes_, &attributes));
  EXPECT_EQ(attributes.flags(), all_attributes_.flags);
  EXPECT_EQ(attributes.xfrm(), all_attributes_.xfrm);
}

// Verify error handling for conversion from attribute list to Attributes.
TEST_F(SecsAttributesTest, ListToAttributesError) {
  std::vector<SecsAttributeBit> v{bad_attribute_};
  std::string str =
      absl::StrCat("SecsAttributeBit specifies a bit position ",
                   static_cast<size_t>(bad_attribute_),
                   " that is larger than the max allowed value of 127");
  EXPECT_LOG(ERROR, str);
  Attributes attributes;
  EXPECT_FALSE(ConvertSecsAttributeRepresentation(v, &attributes));
}

// Verify the correctness of conversion from Attributes to attribute list.
TEST_F(SecsAttributesTest, AttributesToList) {
  std::vector<SecsAttributeBit> list;
  Attributes attributes;
  for (int i = 0; i < attribute_sets_.size(); i++) {
    attributes.set_flags(attribute_sets_[i].flags);
    attributes.set_xfrm(attribute_sets_[i].xfrm);
    EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes, &list));
    EXPECT_EQ(list.size(), 1);
    EXPECT_EQ(list[0], attributes_[i]);
  }

  attributes.set_flags(all_attributes_.flags);
  attributes.set_xfrm(all_attributes_.xfrm);
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes, &list));
  EXPECT_EQ(list.size(), attributes_.size());
  for (int i = 0; i < list.size(); i++) {
    EXPECT_EQ(list[i], attributes_[i]);
  }
}

// Verify the correctness of conversion from AttributeSet to Attributes.
TEST_F(SecsAttributesTest, SetToAttributes) {
  Attributes attributes;
  for (int i = 0; i < attribute_sets_.size(); i++) {
    Attributes attributes;
    EXPECT_TRUE(
        ConvertSecsAttributeRepresentation(attribute_sets_[i], &attributes));
    EXPECT_EQ(attributes.flags(), attribute_sets_[i].flags);
    EXPECT_EQ(attributes.xfrm(), attribute_sets_[i].xfrm);
  }

  EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes_, &attributes));
  EXPECT_EQ(attributes.flags(), all_attributes_.flags);
  EXPECT_EQ(attributes.xfrm(), all_attributes_.xfrm);
}

// Verify the correctness of conversion from Attributes to AttributeSet.
TEST_F(SecsAttributesTest, AttributesToSet) {
  std::vector<SecsAttributeBit> list;
  Attributes attributes;
  SecsAttributeSet attribute_set;

  for (int i = 0; i < attribute_sets_.size(); i++) {
    attributes.set_flags(attribute_sets_[i].flags);
    attributes.set_xfrm(attribute_sets_[i].xfrm);
    EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes, &attribute_set));
    EXPECT_EQ(attributes.flags(), attribute_set.flags);
    EXPECT_EQ(attributes.xfrm(), attribute_set.xfrm);
  }

  attributes.set_flags(all_attributes_.flags);
  attributes.set_xfrm(all_attributes_.xfrm);
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes, &attribute_set));
  EXPECT_EQ(attributes.flags(), all_attributes_.flags);
  EXPECT_EQ(attributes.xfrm(), all_attributes_.xfrm);
}

// Verify the correctness of TestAttribute on a set.
TEST_F(SecsAttributesTest, TestAttributeSet) {
  for (int i = 0; i < attribute_sets_.size(); i++) {
    for (int j = 0; j < attributes_.size(); j++) {
      EXPECT_EQ(TestAttribute(attributes_[j], attribute_sets_[i]), (i == j));
    }
  }
  for (int j = 0; j < attributes_.size(); j++) {
    EXPECT_TRUE(TestAttribute(attributes_[j], all_attributes_));
  }
}

// Verify the error-handling in TestAttribute on a set.
TEST_F(SecsAttributesTest, TestAttributeSetError) {
  std::string str =
      absl::StrCat("SecsAttributeBit specifies a bit position ",
                   static_cast<size_t>(bad_attribute_),
                   " that is larger than the max allowed value of 127");

  EXPECT_LOG(INFO, str);

  EXPECT_FALSE(TestAttribute(bad_attribute_, all_attributes_));
}

// Verify the correctness of TestAttribute on Attributes.
TEST_F(SecsAttributesTest, TestAttributeAttributes) {
  Attributes attributes;
  for (int i = 0; i < attribute_sets_.size(); i++) {
    EXPECT_TRUE(
        ConvertSecsAttributeRepresentation(attribute_sets_[i], &attributes));
    for (int j = 0; j < attributes_.size(); j++) {
      EXPECT_EQ(TestAttribute(attributes_[j], attributes), (i == j));
    }
  }
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(all_attributes_, &attributes));
  for (int j = 0; j < attributes_.size(); j++) {
    EXPECT_TRUE(TestAttribute(attributes_[j], attributes));
  }
}

// Verify the error-handling in TestAttribute on a set.
TEST_F(SecsAttributesTest, TestAttributeAttributesError) {
  std::string str =
      absl::StrCat("SecsAttributeBit specifies a bit position ",
                   static_cast<size_t>(bad_attribute_),
                   " that is larger than the max allowed value of 127");

  EXPECT_LOG(INFO, str);

  Attributes attributes;
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(all_attributes_, &attributes));
  EXPECT_FALSE(TestAttribute(bad_attribute_, attributes));
}

// Verify that SetDefaultSecsAttributesMask creates a mask that is the logical
// NOT of the "do not care" attributes set.
TEST_F(SecsAttributesTest, SetDefaultSecsAttributesMask) {
  Attributes attributes_match_mask_vector;
  EXPECT_THAT(SetDefaultSecsAttributesMask(&attributes_match_mask_vector),
              IsOk());
  SecsAttributeSet attributes_match_mask;
  EXPECT_TRUE(ConvertSecsAttributeRepresentation(attributes_match_mask_vector,
                                                 &attributes_match_mask));

  SecsAttributeSet do_not_care_attributes;
  EXPECT_TRUE(GetDefaultDoNotCareSecsAttributes(&do_not_care_attributes));

  EXPECT_EQ(~attributes_match_mask.flags, do_not_care_attributes.flags);
  EXPECT_EQ(~attributes_match_mask.xfrm, do_not_care_attributes.xfrm);
}

// Verify that SetStrictSecsAttributesMask creates a mask that sets all possible
// attributes bits.
TEST_F(SecsAttributesTest, SetStrictSecsAttributesMask) {
  Attributes attributes_match_mask;
  SetStrictSecsAttributesMask(&attributes_match_mask);

  EXPECT_EQ(attributes_match_mask.flags(), kLongLongAllF);
  EXPECT_EQ(attributes_match_mask.xfrm(), kLongLongAllF);
}

// Verify the correctness of GetPrintableAttributeList on an attribute list.
TEST_F(SecsAttributesTest, GetPrintableAttributeListFromList) {
  std::vector<std::string> printable_list;

  for (int i = 0; i < attribute_sets_.size(); i++) {
    std::vector<SecsAttributeBit> attribute_bit_list = {attributes_[i]};
    GetPrintableAttributeList(attribute_bit_list, &printable_list);
    EXPECT_EQ(printable_list.size(), 1);
    EXPECT_EQ(printable_list[0], attribute_names_[i]);
  }

  GetPrintableAttributeList(attributes_, &printable_list);
  EXPECT_EQ(printable_list.size(), attributes_.size());
  for (int i = 0; i < printable_list.size(); i++) {
    EXPECT_EQ(printable_list[i], attribute_names_[i]);
  }
}

// Verify the correctness of GetPrintableAttributeList on an attribute set.
TEST_F(SecsAttributesTest, GetPrintableAttributeListFromSet) {
  std::vector<std::string> printable_list;

  for (int i = 0; i < attribute_sets_.size(); i++) {
    GetPrintableAttributeList(attribute_sets_[i], &printable_list);
    EXPECT_EQ(printable_list.size(), 1);
    EXPECT_EQ(printable_list[0], attribute_names_[i]);
  }

  GetPrintableAttributeList(all_attributes_, &printable_list);
  EXPECT_EQ(printable_list.size(), attributes_.size());
  for (int i = 0; i < printable_list.size(); i++) {
    EXPECT_EQ(printable_list[i], attribute_names_[i]);
  }
}

// Verify the correctness of GetPrintableAttributeList on Attributes.
TEST_F(SecsAttributesTest, GetPrintableAttributeListFromAttributes) {
  std::vector<std::string> printable_list;
  Attributes attributes;

  for (int i = 0; i < attribute_sets_.size(); i++) {
    EXPECT_TRUE(
        ConvertSecsAttributeRepresentation(attribute_sets_[i], &attributes));
    GetPrintableAttributeList(attributes, &printable_list);
    EXPECT_EQ(printable_list.size(), 1);
    EXPECT_EQ(printable_list[0], attribute_names_[i]);
  }

  EXPECT_TRUE(ConvertSecsAttributeRepresentation(all_attributes_, &attributes));
  GetPrintableAttributeList(attributes, &printable_list);
  EXPECT_EQ(printable_list.size(), attributes_.size());
  for (int i = 0; i < printable_list.size(); i++) {
    EXPECT_EQ(printable_list[i], attribute_names_[i]);
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
