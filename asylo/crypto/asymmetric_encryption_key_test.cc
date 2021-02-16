/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/crypto/asymmetric_encryption_key.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/error_codes.h"

namespace asylo {
namespace {

using ::testing::ByMove;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Return;

class MockAsymmetricEncryptionKey : public AsymmetricEncryptionKey {
 public:
  MOCK_METHOD(AsymmetricEncryptionScheme, GetEncryptionScheme, (),
              (const, override));
  MOCK_METHOD(StatusOr<std::string>, SerializeToDer, (), (const, override));
  MOCK_METHOD(Status, Encrypt,
              (ByteContainerView plaintext, std::vector<uint8_t> *ciphertext),
              (const, override));
};

class MockAsymmetricDecryptionKey : public AsymmetricDecryptionKey {
 public:
  MOCK_METHOD(AsymmetricEncryptionScheme, GetEncryptionScheme, (),
              (const, override));

  MOCK_METHOD(Status, SerializeToDer,
              (CleansingVector<uint8_t> * serialized_key), (const, override));

  MOCK_METHOD(StatusOr<std::unique_ptr<AsymmetricEncryptionKey>>,
              GetEncryptionKey, (), (const, override));

  MOCK_METHOD(Status, Decrypt,
              (ByteContainerView ciphertext,
               CleansingVector<uint8_t> *plaintext),
              (const, override));
};

constexpr AsymmetricEncryptionScheme kMockEncryptionScheme =
    AsymmetricEncryptionScheme::RSA2048_OAEP;

constexpr absl::string_view kMockDer = "asdpoaspodfnasdfpk";

std::unique_ptr<AsymmetricEncryptionKey> CreateMockEncryptionKey() {
  auto mock = absl::make_unique<MockAsymmetricEncryptionKey>();
  EXPECT_CALL(*mock, SerializeToDer).WillOnce(Return(std::string(kMockDer)));
  EXPECT_CALL(*mock, GetEncryptionScheme)
      .WillOnce(Return(kMockEncryptionScheme));
  return std::move(mock);
}

void VerifyMockKeyExpectations(const AsymmetricEncryptionKeyProto &key_proto) {
  EXPECT_TRUE(key_proto.has_key_type());
  EXPECT_THAT(key_proto.key_type(),
              Eq(AsymmetricEncryptionKeyProto::ENCRYPTION_KEY));

  EXPECT_TRUE(key_proto.has_encryption_scheme());
  EXPECT_THAT(key_proto.encryption_scheme(), Eq(kMockEncryptionScheme));

  EXPECT_TRUE(key_proto.has_encoding());
  EXPECT_THAT(key_proto.encoding(),
              Eq(AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER));

  EXPECT_TRUE(key_proto.has_key());
  EXPECT_THAT(key_proto.key(),
              ElementsAreArray(kMockDer.begin(), kMockDer.end()));
}

TEST(AsymmetricEncryptionKeyTest, EncryptionKeyToProto) {
  std::unique_ptr<AsymmetricEncryptionKey> key = CreateMockEncryptionKey();

  AsymmetricEncryptionKeyProto result;
  ASYLO_ASSERT_OK_AND_ASSIGN(result,
                             ConvertToAsymmetricEncryptionKeyProto(*key));

  VerifyMockKeyExpectations(result);
}

TEST(AsymmetricEncryptionKeyTest, DecryptionKeyToProto) {
  MockAsymmetricDecryptionKey key;

  EXPECT_CALL(key, GetEncryptionKey)
      .WillOnce(Return(ByMove(CreateMockEncryptionKey())));

  AsymmetricEncryptionKeyProto result;
  ASYLO_ASSERT_OK_AND_ASSIGN(result,
                             ConvertToAsymmetricEncryptionKeyProto(key));

  VerifyMockKeyExpectations(result);
}

TEST(AsymmetricEncryptionKeyTest, DecryptionKeyToProtoWithFailure) {
  const Status kError(::absl::StatusCode::kAborted, "Nope");

  MockAsymmetricDecryptionKey key;
  EXPECT_CALL(key, GetEncryptionKey).WillOnce(Return(ByMove(kError)));

  StatusOr<AsymmetricEncryptionKeyProto> result =
      ConvertToAsymmetricEncryptionKeyProto(key);
  EXPECT_THAT(result.status(), Eq(kError));
}

}  // namespace
}  // namespace asylo
