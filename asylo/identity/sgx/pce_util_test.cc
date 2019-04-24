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
constexpr AsymmetricEncryptionScheme kSupportedSchemes[] = {RSA3072_OAEP};

// The crypto suite corresponding to each scheme in kSupportedSchemes.
constexpr uint8_t kTranslatedSchemes[] = {PCE_ALG_RSA_OAEP_3072};

class PceUtilTest : public ::testing::Test {
 public:
  void SetUp() override {
    supported_schemes_.reserve(ABSL_ARRAYSIZE(kSupportedSchemes));
    for (int i = 0; i < ABSL_ARRAYSIZE(kSupportedSchemes); ++i) {
      ASSERT_TRUE(supported_schemes_
                      .emplace(kSupportedSchemes[i], kTranslatedSchemes[i])
                      .second);
    }

    for (int i = 0; i < AsymmetricEncryptionScheme_ARRAYSIZE; ++i) {
      if (AsymmetricEncryptionScheme_IsValid(i)) {
        AsymmetricEncryptionScheme scheme =
            static_cast<AsymmetricEncryptionScheme>(i);
        if (!supported_schemes_.contains(scheme)) {
          unsupported_schemes_.push_back(scheme);
        }
      }
    }
  }

  absl::flat_hash_map<AsymmetricEncryptionScheme, uint8_t> supported_schemes_;
  std::vector<AsymmetricEncryptionScheme> unsupported_schemes_;
};

TEST_F(PceUtilTest, AsymmetricEncryptionSchemeToPceCryptoSuiteSupported) {
  for (const auto &pair : supported_schemes_) {
    EXPECT_THAT(AsymmetricEncryptionSchemeToPceCryptoSuite(pair.first),
                Optional(pair.second));
  }
}

TEST_F(PceUtilTest, AsymmetricEncryptionSchemeToPceCryptoSuiteUnsupported) {
  for (AsymmetricEncryptionScheme scheme : unsupported_schemes_) {
    EXPECT_THAT(AsymmetricEncryptionSchemeToPceCryptoSuite(scheme),
                Eq(absl::nullopt));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
