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

#include "asylo/identity/sgx/proto_format.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/miscselect.pb.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/identity/sgx/secs_miscselect.h"
#include "asylo/identity/util/sha256_hash.pb.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::HasSubstr;
using ::testing::Test;

TEST(ProtoFormatTest, CodeIdentityHasAttributesByName) {
  CodeIdentity identity;
  SetSelfCodeIdentity(&identity);
  std::string text = FormatProto(identity);

  std::vector<absl::string_view> named_attributes;
  GetPrintableAttributeList(identity.attributes(), &named_attributes);
  for (const auto attribute : named_attributes) {
    EXPECT_THAT(text, HasSubstr(std::string(attribute)));
  }
}

TEST(ProtoFormatTest, MiscselectBitsByName) {
  Miscselect miscselect;
  miscselect.set_value(UINT32_C(1)
                       << static_cast<size_t>(SecsMiscselectBit::EXINFO));
  std::string text = FormatProto(miscselect);

  std::vector<absl::string_view> named_miscselect_bits =
      GetPrintableMiscselectList(miscselect);
  for (const auto miscselect_bit : named_miscselect_bits) {
    EXPECT_THAT(text, HasSubstr(std::string(miscselect_bit)));
  }
}

TEST(ProtoFormatTest, CodeIdentityHasMiscselectBitsByName) {
  CodeIdentity identity;
  SetSelfCodeIdentity(&identity);
  std::string text = FormatProto(identity);

  std::vector<absl::string_view> named_miscselect_bits =
      GetPrintableMiscselectList(identity.miscselect());
  for (const auto miscselect_bit : named_miscselect_bits) {
    EXPECT_THAT(text, HasSubstr(std::string(miscselect_bit)));
  }
}

TEST(ProtoFormatTest, CodeIdentityHasHexEncodedBytesFields) {
  CodeIdentity identity;
  SetSelfCodeIdentity(&identity);
  std::string text = FormatProto(identity);

  EXPECT_THAT(text,
              HasSubstr(absl::BytesToHexString(identity.mrenclave().hash())));
  EXPECT_THAT(text,
              HasSubstr(absl::BytesToHexString(
                  identity.signer_assigned_identity().mrsigner().hash())));
}

TEST(ProtoFormatTest, CodeIdentityMatchSpecHasAttributesByName) {
  CodeIdentityMatchSpec match_spec;
  SetDefaultMatchSpec(&match_spec);
  std::string text = FormatProto(match_spec);

  std::vector<absl::string_view> named_attributes;
  GetPrintableAttributeList(match_spec.attributes_match_mask(),
                            &named_attributes);
  for (const auto attribute : named_attributes) {
    EXPECT_THAT(text, HasSubstr(std::string(attribute)));
  }
}

TEST(ProtoFormatTest, CodeIdentityMatchSpecHasMiscselectBitsByName) {
  CodeIdentityMatchSpec match_spec;
  SetDefaultMatchSpec(&match_spec);
  std::string text = FormatProto(match_spec);

  std::vector<absl::string_view> named_miscselect_bits =
      GetPrintableMiscselectList(match_spec.miscselect_match_mask());
  for (const auto miscselect_bit : named_miscselect_bits) {
    EXPECT_THAT(text, HasSubstr(std::string(miscselect_bit)));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
