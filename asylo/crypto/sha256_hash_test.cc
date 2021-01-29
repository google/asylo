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

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha_hash_test.h"

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

class Sha256HashTest : public ShaHashTest<Sha256Hash> {
 public:
  using ShaHashType = Sha256Hash;
  Sha256HashTest()
      : ShaHashTest(Sha256HashOptions::kDigestLength,
                    Sha256HashOptions::kHashAlgorithm,
                    Sha256HashOptions::EvpMd(), kTestVector1, kResult1,
                    kTestVector2, kResult2, kSuffix) {}
};

typedef testing::Types<Sha256HashTest> ShaHashTypes;
INSTANTIATE_TYPED_TEST_SUITE_P(Sha256, HashTest, ShaHashTypes);

}  // namespace
}  // namespace asylo
