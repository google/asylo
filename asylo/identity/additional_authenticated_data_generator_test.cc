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

#include "asylo/identity/additional_authenticated_data_generator.h"

#include <functional>
#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Test;

// Test information for PCE Get Info AAD generator.
const char kGetPceInfoUuidHex[] = "00000000000000000000000000000000";
const char kGetPceInfoPurposeHex[] = "00000000000000000000000000000000";

// Test information for Create PCE Signed Report AAD generator.
const char kPceSignReportUuidHex[] = "4153594c4f205349474e5245504f5254";
const char kPceSignReportPurposeHex[] = "00000000000000000000000000000000";

// Test information for EKEP AAD generator.
const char kEkepUuidHex[] = "4153594c4f20454b4550000000000000";
const char kEkepPurposeHex[] = "00000000000000000000000000000000";

// Data and the SHA-256 hash of it.
const char kDataHex[] = "436f66666565206973206c6966652e0a";
const char kDataHashHex[] =
    "08adf7f72bdf800b42573a341ac5b51471433ec1659944425f29bb90ef12f69c";

void GeneratesExpectedValue(
    std::unique_ptr<AdditionalAuthenticatedDataGenerator> generator,
    const std::string &uuid, const std::string &purpose) {
  UnsafeBytes<kAdditionalAuthenticatedDataSize> aad_bytes;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      aad_bytes, generator->Generate(absl::HexStringToBytes(kDataHex)));

  std::string aad(aad_bytes.begin(), aad_bytes.end());
  ASSERT_EQ(aad.size(), kSha256DigestLength +
                            kAdditionalAuthenticatedDataPurposeSize +
                            kAdditionalAuthenticatedDataUuidSize);

  EXPECT_EQ(aad.substr(0, kSha256DigestLength),
            absl::HexStringToBytes(kDataHashHex));
  EXPECT_EQ(
      aad.substr(kSha256DigestLength, kAdditionalAuthenticatedDataPurposeSize),
      purpose);
  EXPECT_EQ(
      aad.substr(kSha256DigestLength + kAdditionalAuthenticatedDataPurposeSize,
                 kAdditionalAuthenticatedDataUuidSize),
      uuid);
}

// Verifies that an AdditionalAuthenticatedDataGenerator for Get PCE Info
// produces correctly formatted data.
TEST(AdditionalAuthenticatedDataGeneratorTest, GetPceInfoGeneratorSuccess) {
  GeneratesExpectedValue(
      AdditionalAuthenticatedDataGenerator::CreateGetPceInfoAadGenerator(),
      absl::HexStringToBytes(kGetPceInfoUuidHex),
      absl::HexStringToBytes(kGetPceInfoPurposeHex));
}

// Verifies that an AdditionalAuthenticatedDataGenerator for PCE Sign Report
// produces correctly formatted data.
TEST(AdditionalAuthenticatedDataGeneratorTest,
     PceSignedReportGeneratorSuccess) {
  GeneratesExpectedValue(
      AdditionalAuthenticatedDataGenerator::CreatePceSignReportAadGenerator(),
      absl::HexStringToBytes(kPceSignReportUuidHex),
      absl::HexStringToBytes(kPceSignReportPurposeHex));
}

// Verifies that an AdditionalAuthenticatedDataGenerator for EKEP produces
// correctly formatted data.
TEST(AdditionalAuthenticatedDataGeneratorTest, EkepGeneratorSuccess) {
  GeneratesExpectedValue(
      AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator(),
      absl::HexStringToBytes(kEkepUuidHex),
      absl::HexStringToBytes(kEkepPurposeHex));
}

}  // namespace
}  // namespace asylo
