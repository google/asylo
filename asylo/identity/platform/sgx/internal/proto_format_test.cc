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

#include "asylo/identity/platform/sgx/internal/proto_format.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes_util.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/miscselect.pb.h"
#include "asylo/identity/platform/sgx/miscselect_util.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::HasSubstr;
using ::testing::Test;

constexpr char kValidCpuSvnHexString[] = "00112233445566778899aabbccddeeff";

TEST(ProtoFormatTest, SgxIdentityHasAttributesByName) {
  const SgxIdentity identity = GetSelfSgxIdentity();
  std::string text = FormatProto(identity);

  std::vector<absl::string_view> named_attributes =
      GetPrintableAttributeList(identity.code_identity().attributes());
  for (const auto attribute : named_attributes) {
    EXPECT_THAT(text, HasSubstr(std::string(attribute)));
  }
}

TEST(ProtoFormatTest, SgxIdentityHasCpuSvnAsHexString) {
  SgxIdentity identity = GetSelfSgxIdentity();

  CpuSvn cpu_svn;
  cpu_svn.set_value(absl::HexStringToBytes(kValidCpuSvnHexString));
  *identity.mutable_machine_configuration()->mutable_cpu_svn() = cpu_svn;
  ASSERT_TRUE(IsValidSgxIdentity(identity));

  std::string text = FormatProto(identity);
  EXPECT_THAT(text, HasSubstr(absl::StrCat("0x", kValidCpuSvnHexString)));
}

TEST(ProtoFormatTest, MiscselectBitsByName) {
  Miscselect miscselect;
  miscselect.set_value(UINT32_C(1)
                       << static_cast<size_t>(MiscselectBit::EXINFO));
  std::string text = FormatProto(miscselect);

  std::vector<absl::string_view> named_miscselect_bits =
      GetPrintableMiscselectList(miscselect);
  for (const auto miscselect_bit : named_miscselect_bits) {
    EXPECT_THAT(text, HasSubstr(std::string(miscselect_bit)));
  }
}

TEST(ProtoFormatTest, SgxIdentityHasMiscselectBitsByName) {
  const SgxIdentity identity = GetSelfSgxIdentity();
  std::string text = FormatProto(identity);

  std::vector<absl::string_view> named_miscselect_bits =
      GetPrintableMiscselectList(identity.code_identity().miscselect());
  for (const auto miscselect_bit : named_miscselect_bits) {
    EXPECT_THAT(text, HasSubstr(std::string(miscselect_bit)));
  }
}

TEST(ProtoFormatTest, SgxIdentityHasHexEncodedBytesFields) {
  const SgxIdentity identity = GetSelfSgxIdentity();
  std::string text = FormatProto(identity);

  EXPECT_THAT(text,
              HasSubstr(absl::StrCat(
                  "0x", absl::BytesToHexString(
                            identity.code_identity().mrenclave().hash()))));
  EXPECT_THAT(text,
              HasSubstr(absl::StrCat(
                  "0x", absl::BytesToHexString(identity.code_identity()
                                                   .signer_assigned_identity()
                                                   .mrsigner()
                                                   .hash()))));
}

TEST(ProtoFormatTest, SgxIdentityMatchSpecHasAttributesByName) {
  SgxIdentityMatchSpec match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      match_spec,
      CreateSgxIdentityMatchSpec(SgxIdentityMatchSpecOptions::DEFAULT));
  std::string text = FormatProto(match_spec);

  std::vector<absl::string_view> named_attributes = GetPrintableAttributeList(
      match_spec.code_identity_match_spec().attributes_match_mask());
  for (const auto attribute : named_attributes) {
    EXPECT_THAT(text, HasSubstr(std::string(attribute)));
  }
}

TEST(ProtoFormatTest, SgxIdentityMatchSpecHasMiscselectBitsByName) {
  SgxIdentityMatchSpec match_spec;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      match_spec,
      CreateSgxIdentityMatchSpec(SgxIdentityMatchSpecOptions::DEFAULT));
  std::string text = FormatProto(match_spec);

  std::vector<absl::string_view> named_miscselect_bits =
      GetPrintableMiscselectList(
          match_spec.code_identity_match_spec().miscselect_match_mask());
  for (const auto miscselect_bit : named_miscselect_bits) {
    EXPECT_THAT(text, HasSubstr(std::string(miscselect_bit)));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
