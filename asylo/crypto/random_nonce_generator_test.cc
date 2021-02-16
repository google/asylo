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

#include "asylo/crypto/random_nonce_generator.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_join.h"
#include "absl/types/span.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Test;

constexpr size_t kAesGcmNonceSize = 12;
constexpr size_t kBadNonceSize = 11;
constexpr size_t kNoncePartSize = 4;
constexpr size_t kNumberOfGeneratedNonces = 21;

// Tests that NonceSize() returns the correct nonce size for each factory.
TEST(RandomNonceGeneratorTest, RandomNonceGeneratorNonceSize) {
  std::unique_ptr<RandomNonceGenerator> nonce_generator =
      RandomNonceGenerator::CreateAesGcmNonceGenerator();
  EXPECT_EQ(nonce_generator->NonceSize(), kAesGcmNonceSize);
}

// Tests that generated nonces have no collisions in a sampling.
TEST(RandomNonceGeneratorTest, RandomNonceGeneratorGeneratesNoCollisions) {
  // An acceptable level of flakiness was determined to be about 2^-20 (or about
  // one in a million), so the chance of collision could be at most that.
  // Let:
  //   f = 2 ^ -20 = P(collision)
  //   x = kNumberOfGeneratedNonces
  //   p = kNoncePartSize * 8 (size in bits)
  //   n = kAesGcmNonceSize * 8 (size in bits)
  // Using the square approximation of the birthday problem, the probability of
  // a collision is:
  //   P(collision) = ((floor(n / p) * x) ^ 2) / (2 ^ p)
  // This implies:
  //   x = sqrt((2 ^ p) * f) / floor(n / p) = 21

  std::unique_ptr<RandomNonceGenerator> nonce_generator =
      RandomNonceGenerator::CreateAesGcmNonceGenerator();
  std::vector<uint8_t> nonce(kAesGcmNonceSize);
  absl::flat_hash_set<std::string> generated_nonces;
  for (int i = 0; i < kNumberOfGeneratedNonces; i++) {
    ASYLO_ASSERT_OK(nonce_generator->NextNonce(absl::MakeSpan(nonce)));
    for (int j = 0; j < kAesGcmNonceSize; j += kNoncePartSize) {
      EXPECT_TRUE(
          generated_nonces
              .emplace(nonce.cbegin() + j, nonce.cbegin() + j + kNoncePartSize)
              .second);
    }
  }
}

// Tests that NextNonce() returns a non-OK Status if it is given a nonce with
// an invalid size.
TEST(RandomNonceGeneratorTest, RandomNonceGeneratorIncorrectNonceSize) {
  std::unique_ptr<RandomNonceGenerator> nonce_generator =
      RandomNonceGenerator::CreateAesGcmNonceGenerator();
  std::vector<uint8_t> nonce(kBadNonceSize);
  EXPECT_THAT(nonce_generator->NextNonce(absl::MakeSpan(nonce)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace asylo
