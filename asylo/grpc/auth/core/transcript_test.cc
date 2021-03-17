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

#include "asylo/grpc/auth/core/transcript.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/hash_interface.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace grpc {
namespace auth {
namespace {

using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::ZeroCopyInputStream;

constexpr char kData1[] = "A very uninteresting string.";
constexpr char kData2[] = "Enclave Key Exchange Protocol";

const int kInputStreamBlockSize = 4;

// FakeHash implements the HashInterface with a trivial hash algorithm: the hash
// is simply a concatenation of all bytes that have been added.
class FakeHash final : public HashInterface {
 public:
  HashAlgorithm GetHashAlgorithm() const override {
    return HashAlgorithm::UNKNOWN_HASH_ALGORITHM;
  }
  size_t DigestSize() const override { return 0; }
  void Init() override {}
  void Update(ByteContainerView data) override {
    std::copy(data.begin(), data.end(), std::back_inserter(data_));
  }

  Status CumulativeHash(std::vector<uint8_t> *digest) const override {
    *digest = data_;
    return absl::OkStatus();
  }

 private:
  std::vector<uint8_t> data_;
};

// Utility method for calling Transcript::Add on |transcript| with the contents
// of |input|.
void AddFromString(const std::string &input, Transcript *transcript) {
  std::unique_ptr<ZeroCopyInputStream> stream(
      new ArrayInputStream(input.data(), input.size(), kInputStreamBlockSize));
  transcript->Add(stream.get());
}

// A test fixture is required for typed tests.
template <typename T>
class TranscriptTest : public ::testing::Test {};

typedef ::testing::Types<FakeHash, Sha256Hash> TestTypes;

TYPED_TEST_SUITE(TranscriptTest, TestTypes);

// Verify that the hash function for a Transcript can only be set once.
TYPED_TEST(TranscriptTest, SetHasherSucceedsOnce) {
  Transcript transcript;

  EXPECT_TRUE(transcript.SetHasher(new TypeParam()));

  auto hasher = absl::make_unique<TypeParam>();
  EXPECT_FALSE(transcript.SetHasher(hasher.get()));
}

// Verify that Hash fails if no hash function is set.
TYPED_TEST(TranscriptTest, HashFailsWithNoHashFunction) {
  Transcript transcript;
  AddFromString(kData1, &transcript);

  std::string digest;
  EXPECT_FALSE(transcript.Hash(&digest));
}

// Verify that the hash returned from Hash is the same as the hash computed by
// the underlying hash function.
TYPED_TEST(TranscriptTest, HashSameAsUnderlyingHash) {
  TypeParam hash;
  hash.Update(kData1);
  hash.Update(kData2);
  std::vector<uint8_t> digest1;
  ASSERT_THAT(hash.CumulativeHash(&digest1), IsOk());

  Transcript transcript;
  AddFromString(kData1, &transcript);
  AddFromString(kData2, &transcript);
  EXPECT_TRUE(transcript.SetHasher(new TypeParam()));
  std::string digest2;
  ASSERT_TRUE(transcript.Hash(&digest2));

  EXPECT_EQ(ByteContainerView(digest1), ByteContainerView(digest2));
}

// Verify that Hash returns the same hash, regardless of whether bytes were
// added before or after the hash function was set.
TYPED_TEST(TranscriptTest, AddBytesAndHash) {
  Transcript transcript1;
  Transcript transcript2;
  Transcript transcript3;

  // Transcript 1: Set the hash interface, then add all the bytes.
  EXPECT_TRUE(transcript1.SetHasher(new TypeParam()));
  AddFromString(kData1, &transcript1);
  AddFromString(kData2, &transcript1);

  // Transcript 2: Add some bytes, set hash interface, add remaining bytes.
  AddFromString(kData1, &transcript2);
  EXPECT_TRUE(transcript2.SetHasher(new TypeParam()));
  AddFromString(kData2, &transcript2);

  // Transcript 3: Add all bytes, then set hash interface.
  AddFromString(kData1, &transcript3);
  AddFromString(kData2, &transcript3);
  EXPECT_TRUE(transcript3.SetHasher(new TypeParam()));

  std::string running_hash1;
  std::string running_hash2;
  std::string running_hash3;
  ASSERT_TRUE(transcript1.Hash(&running_hash1));
  ASSERT_TRUE(transcript2.Hash(&running_hash2));
  ASSERT_TRUE(transcript3.Hash(&running_hash3));

  // All transcripts should have the same running hash.
  EXPECT_EQ(running_hash1, running_hash2);
  EXPECT_EQ(running_hash2, running_hash3);
}

}  // namespace
}  // namespace auth
}  // namespace grpc
}  // namespace asylo
