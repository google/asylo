/*
 * Copyright 2021 Asylo authors
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
 */

#include "asylo/crypto/sha384_hash.h"

#include <openssl/digest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha_hash_test.h"

namespace asylo {
namespace {

// The following two test vectors are taken from
// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA384.pdf.

constexpr char kTestVector1[] = "abc";
constexpr char kResult1[] =
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1"
    "e7cc2358baeca134c825a7";

constexpr char kTestVector2[] =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjk"
    "lmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
constexpr char kResult2[] =
    "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a55"
    "7e2db966c3e9fa91746039";

// kTestVector2 without kTestVector1 prefix.
constexpr char kSuffix[] =
    "defghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmn"
    "opqklmnopqrlmnopqrsmnopqrstnopqrstu";

class Sha384HashTest : public ShaHashTest<Sha384Hash> {
 public:
  using ShaHashType = Sha384Hash;
  Sha384HashTest()
      : ShaHashTest(Sha384HashOptions::kDigestLength,
                    Sha384HashOptions::kHashAlgorithm,
                    Sha384HashOptions::EvpMd(), kTestVector1, kResult1,
                    kTestVector2, kResult2, kSuffix) {}
};

typedef testing::Types<Sha384HashTest> ShaHashTypes;
INSTANTIATE_TYPED_TEST_SUITE_P(Sha384, HashTest, ShaHashTypes);

}  // namespace
}  // namespace asylo
