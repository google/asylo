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

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/proto_format.h"
#include "asylo/identity/sgx/secs_attributes.h"
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

  std::vector<std::string> named_attributes;
  GetPrintableAttributeList(identity.attributes(), &named_attributes);
  for (const std::string &attribute : named_attributes) {
    EXPECT_THAT(text, HasSubstr(attribute));
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

  std::vector<std::string> named_attributes;
  GetPrintableAttributeList(match_spec.attributes_match_mask(),
                            &named_attributes);
  for (const std::string &attribute : named_attributes) {
    EXPECT_THAT(text, HasSubstr(attribute));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
