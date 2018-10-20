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

#include "asylo/crypto/sha256_hash.h"

#include <openssl/sha.h>

#include <cstdint>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

// The following two test vectors are taken from
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf.

constexpr char kTestVector1[] = "abc";
constexpr char kResult1[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

constexpr char kTestVector2[] =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
constexpr char kResult2[] =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

// kTestVector2 without kTestVector1 prefix.
constexpr char kSuffix[] =
    "dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

TEST(Sha256HashTest, Algorithm) {
  Sha256Hash hash;
  EXPECT_EQ(hash.GetHashAlgorithm(), HashAlgorithm::SHA256);
}

TEST(Sha256HashTest, DigestSize) {
  Sha256Hash hash;
  EXPECT_EQ(hash.DigestSize(), SHA256_DIGEST_LENGTH);
}

// The following two tests verify the correctness of the Sha256Hash wrapper
// implementation by testing against standard SHA test vectors.

TEST(Sha256HashTest, TestVector1) {
  Sha256Hash hash;
  hash.Update(kTestVector1);
  std::vector<uint8_t> digest;
  ASSERT_THAT(hash.CumulativeHash(&digest), IsOk());
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            kResult1);
}

TEST(Sha256HashTest, TestVector2) {
  Sha256Hash hash;
  hash.Update(kTestVector2);
  std::vector<uint8_t> digest;
  ASSERT_THAT(hash.CumulativeHash(&digest), IsOk());
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            kResult2);
}

// Verify that calling Init() after addition of some data resets the object to
// a clean state, allowing a new hash operation to take place.
TEST(Sha256HashTest, InitBetweenUpdates) {
  Sha256Hash hash;
  hash.Update(kTestVector1);

  hash.Init();

  hash.Update(kTestVector2);
  std::vector<uint8_t> digest;
  ASSERT_THAT(hash.CumulativeHash(&digest), IsOk());
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            kResult2);
}

// Verify that the correct hash is computed when the input is added over several
// calls to Update.
TEST(Sha256HashTest, MultipleUpdates) {
  Sha256Hash hash;
  hash.Update(kTestVector1);
  std::vector<uint8_t> digest;
  ASSERT_THAT(hash.CumulativeHash(&digest), IsOk());
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            kResult1);

  hash.Update(kSuffix);
  ASSERT_THAT(hash.CumulativeHash(&digest), IsOk());
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            kResult2);
}

}  // namespace
}  // namespace asylo
