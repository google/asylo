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

#include "asylo/identity/sgx/pce_util.h"

#include <cstdint>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"
#include "asylo/crypto/algorithms.pb.h"
#include "QuoteGeneration/psw/pce_wrapper/inc/sgx_pce.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::Optional;

// All encryption schemes supported by the PCE.
constexpr AsymmetricEncryptionScheme kSupportedEncryptionSchemes[] = {
    RSA3072_OAEP};

// The crypto suite corresponding to each scheme in kSupportedEncryptionSchemes.
constexpr uint8_t kTranslatedEncryptionSchemes[] = {PCE_ALG_RSA_OAEP_3072};

// All signature schemes supported by the PCE.
constexpr SignatureScheme kSupportedSignatureSchemes[] = {ECDSA_P256_SHA256};

// The signature scheme corresponding to each scheme in
// kSupportedSignatureSchemes.
constexpr uint8_t kTranslatedSignatureSchemes[] = {PCE_NIST_P256_ECDSA_SHA256};

class PceUtilTest : public ::testing::Test {
 public:
  void SetUp() override {
    supported_encryption_schemes_.reserve(
        ABSL_ARRAYSIZE(kSupportedEncryptionSchemes));
    for (int i = 0; i < ABSL_ARRAYSIZE(kSupportedEncryptionSchemes); ++i) {
      ASSERT_TRUE(supported_encryption_schemes_
                      .emplace(kSupportedEncryptionSchemes[i],
                               kTranslatedEncryptionSchemes[i])
                      .second);
    }
    for (int i = 0; i < AsymmetricEncryptionScheme_ARRAYSIZE; ++i) {
      if (AsymmetricEncryptionScheme_IsValid(i)) {
        AsymmetricEncryptionScheme scheme =
            static_cast<AsymmetricEncryptionScheme>(i);
        if (!supported_encryption_schemes_.contains(scheme)) {
          unsupported_encryption_schemes_.push_back(scheme);
        }
      }
    }

    supported_signature_schemes_.reserve(
        ABSL_ARRAYSIZE(kSupportedSignatureSchemes));
    for (int i = 0; i < ABSL_ARRAYSIZE(kSupportedSignatureSchemes); ++i) {
      ASSERT_TRUE(supported_signature_schemes_
                      .emplace(kSupportedSignatureSchemes[i],
                               kTranslatedSignatureSchemes[i])
                      .second);
    }
    for (int i = 0; i < SignatureScheme_ARRAYSIZE; ++i) {
      if (SignatureScheme_IsValid(i)) {
        SignatureScheme scheme = static_cast<SignatureScheme>(i);
        if (!supported_signature_schemes_.contains(scheme)) {
          unsupported_signature_schemes_.push_back(scheme);
        }
      }
    }
  }

  absl::flat_hash_map<AsymmetricEncryptionScheme, uint8_t>
      supported_encryption_schemes_;
  absl::flat_hash_map<SignatureScheme, uint8_t> supported_signature_schemes_;

  std::vector<AsymmetricEncryptionScheme> unsupported_encryption_schemes_;
  std::vector<SignatureScheme> unsupported_signature_schemes_;
};

TEST_F(PceUtilTest, AsymmetricEncryptionSchemeToPceCryptoSuiteSupported) {
  for (const auto &pair : supported_encryption_schemes_) {
    EXPECT_THAT(AsymmetricEncryptionSchemeToPceCryptoSuite(pair.first),
                Optional(pair.second));
  }
}

TEST_F(PceUtilTest, AsymmetricEncryptionSchemeToPceCryptoSuiteUnsupported) {
  for (AsymmetricEncryptionScheme scheme : unsupported_encryption_schemes_) {
    EXPECT_THAT(AsymmetricEncryptionSchemeToPceCryptoSuite(scheme),
                Eq(absl::nullopt));
  }
}

TEST_F(PceUtilTest, SignatureSchemeToPceSignatureSchemeSupported) {
  for (const auto &pair : supported_signature_schemes_) {
    EXPECT_THAT(SignatureSchemeToPceSignatureScheme(pair.first),
                Optional(pair.second));
  }
}

TEST_F(PceUtilTest, SignatureSchemeToPceSignatureSchemeUnsupported) {
  for (SignatureScheme scheme : unsupported_signature_schemes_) {
    EXPECT_THAT(SignatureSchemeToPceSignatureScheme(scheme), Eq(absl::nullopt));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
