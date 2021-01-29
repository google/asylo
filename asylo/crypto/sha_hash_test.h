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

#ifndef ASYLO_CRYPTO_SHA_HASH_TEST_H_
#define ASYLO_CRYPTO_SHA_HASH_TEST_H_

#include <openssl/base.h>
#include <openssl/digest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha_hash.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {

template <typename T>
using HashTest = T;

TYPED_TEST_SUITE_P(HashTest);

// A type-parametrized test suite for extensions of ShaHashTest.
template <typename T>
class ShaHashTest : public testing::Test {
 public:
  /* The parameters for ShaHashTest() should be as follows:
   *   digest_len      - the output length of the hash, in bytes.
   *   hash_algorithm  - the associated enum value from HashAlgorithm.
   *   evp_hash        - the BoringSSL structure used to implement the hash.
   *   test_vector_1   - a sample message.
   *   result_1        - the result of hashing test_vector_1.
   *   test_vector_2   - a sample message with text_vector_1 as a prefix.
   *   result_2        - the result of hashing test_vector_2.
   *   suffix          - test_vector_2 without the test_vector_1 prefix.
   */
  ShaHashTest(int digest_len, HashAlgorithm hash_algorithm,
              const EVP_MD* evp_hash, std::string test_vector_1,
              std::string result_1, std::string test_vector_2,
              std::string result_2, std::string suffix)
      : digest_len_(digest_len),
        hash_algorithm_(hash_algorithm),
        evp_hash_(evp_hash),
        test_vector_1_(test_vector_1),
        result_1_(result_1),
        test_vector_2_(test_vector_2),
        result_2_(result_2),
        suffix_(suffix) {}

  int digest_len_;
  HashAlgorithm hash_algorithm_;
  const EVP_MD* evp_hash_;

  std::string test_vector_1_;
  std::string result_1_;
  std::string test_vector_2_;
  std::string result_2_;
  std::string suffix_;
};

TYPED_TEST_P(HashTest, Algorithm) {
  typename TestFixture::ShaHashType hash;
  EXPECT_EQ(hash.GetHashAlgorithm(), this->hash_algorithm_);
}

TYPED_TEST_P(HashTest, DigestSize) {
  typename TestFixture::ShaHashType hash;
  EXPECT_EQ(hash.DigestSize(), this->digest_len_);
}

// The following two tests verify the correctness of the ShaHash wrapper
// implementation by testing against standard SHA test vectors.

TYPED_TEST_P(HashTest, TestVector1) {
  typename TestFixture::ShaHashType hash;
  hash.Update(this->test_vector_1_);
  std::vector<uint8_t> digest;
  ASYLO_ASSERT_OK(hash.CumulativeHash(&digest));
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            this->result_1_);
}

TYPED_TEST_P(HashTest, TestVector2) {
  typename TestFixture::ShaHashType hash;
  hash.Update(this->test_vector_2_);
  std::vector<uint8_t> digest;
  ASYLO_ASSERT_OK(hash.CumulativeHash(&digest));
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            this->result_2_);
}

// Verify that calling Init() after addition of some data resets the object to
// a clean state, allowing a new hash operation to take place.
TYPED_TEST_P(HashTest, InitBetweenUpdates) {
  typename TestFixture::ShaHashType hash;
  hash.Update(this->test_vector_1_);

  hash.Init();

  hash.Update(this->test_vector_2_);
  std::vector<uint8_t> digest;
  ASYLO_ASSERT_OK(hash.CumulativeHash(&digest));
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            this->result_2_);
}

// Verify that the correct hash is computed when the input is added over several
// calls to Update.
TYPED_TEST_P(HashTest, MultipleUpdates) {
  typename TestFixture::ShaHashType hash;
  hash.Update(this->test_vector_1_);
  std::vector<uint8_t> digest;
  ASYLO_ASSERT_OK(hash.CumulativeHash(&digest));
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            this->result_1_);

  hash.Update(this->suffix_);
  ASYLO_ASSERT_OK(hash.CumulativeHash(&digest));
  EXPECT_EQ(absl::BytesToHexString(CopyToByteContainer<std::string>(digest)),
            this->result_2_);
}

// Verify that the correct Bssl hash function is returned.
TYPED_TEST_P(HashTest, BsslHashFunction) {
  typename TestFixture::ShaHashType hash;
  hash.Init();

  EXPECT_EQ(hash.GetBsslHashFunction(), this->evp_hash_);
}

REGISTER_TYPED_TEST_SUITE_P(HashTest, Algorithm, DigestSize, TestVector1,
                            TestVector2, InitBetweenUpdates, MultipleUpdates,
                            BsslHashFunction);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SHA_HASH_TEST_H_
