/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/platform/sgx/internal/ppid_ek.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::Gt;

TEST(PpidEkTest, GetPpidEkProtoTest) {
  auto ek = GetPpidEkProto();
  EXPECT_TRUE(ek.has_key());
  EXPECT_THAT(ek.key().size(), Gt(3072/8));

  EXPECT_TRUE(ek.has_key_type());
  EXPECT_THAT(ek.key_type(), Eq(AsymmetricEncryptionKeyProto::ENCRYPTION_KEY));

  EXPECT_TRUE(ek.has_encoding());
  EXPECT_THAT(ek.encoding(), Eq(ASYMMETRIC_KEY_PEM));

  EXPECT_TRUE(ek.has_encryption_scheme());
  EXPECT_THAT(ek.encryption_scheme(), Eq(RSA3072_OAEP));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
