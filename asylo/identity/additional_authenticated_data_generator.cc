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

#include <cstdint>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr uint8_t kGetPceInfoUuid[kAdditionalAuthenticatedDataUuidSize] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t kGetPceInfoPurpose[kAdditionalAuthenticatedDataPurposeSize] =
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

constexpr uint8_t kPceSignReportUuid[kAdditionalAuthenticatedDataUuidSize] = {
    0x41, 0x53, 0x59, 0x4c, 0x4f, 0x20, 0x53, 0x49,
    0x47, 0x4e, 0x52, 0x45, 0x50, 0x4f, 0x52, 0x54};
constexpr uint8_t
    kPceSignReportPurpose[kAdditionalAuthenticatedDataPurposeSize] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

constexpr uint8_t kEkepUuid[kAdditionalAuthenticatedDataUuidSize] = {
    0x41, 0x53, 0x59, 0x4c, 0x4f, 0x20, 0x45, 0x4b,
    0x45, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t kEkepPurpose[kAdditionalAuthenticatedDataPurposeSize] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

}  // namespace

AdditionalAuthenticatedDataGenerator::AdditionalAuthenticatedDataGenerator(
    UnsafeBytes<kAdditionalAuthenticatedDataUuidSize> uuid,
    UnsafeBytes<kAdditionalAuthenticatedDataPurposeSize> purpose)
    : uuid_(uuid), purpose_(purpose) {}

std::unique_ptr<AdditionalAuthenticatedDataGenerator>
AdditionalAuthenticatedDataGenerator::CreateGetPceInfoAadGenerator() {
  return absl::make_unique<AdditionalAuthenticatedDataGenerator>(
      kGetPceInfoUuid, kGetPceInfoPurpose);
}

std::unique_ptr<AdditionalAuthenticatedDataGenerator>
AdditionalAuthenticatedDataGenerator::CreatePceSignReportAadGenerator() {
  return absl::make_unique<AdditionalAuthenticatedDataGenerator>(
      kPceSignReportUuid, kPceSignReportPurpose);
}

std::unique_ptr<AdditionalAuthenticatedDataGenerator>
AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator() {
  return absl::make_unique<AdditionalAuthenticatedDataGenerator>(kEkepUuid,
                                                                 kEkepPurpose);
}

StatusOr<UnsafeBytes<kAdditionalAuthenticatedDataSize>>
AdditionalAuthenticatedDataGenerator::Generate(ByteContainerView data) const {
  Sha256Hash hasher;
  hasher.Init();
  hasher.Update(data);
  std::vector<uint8_t> hash;
  ASYLO_RETURN_IF_ERROR(hasher.CumulativeHash(&hash));
  UnsafeBytes<kAdditionalAuthenticatedDataSize> aad;
  if (aad.replace(0, hash) != hasher.DigestSize()) {
    return absl::InternalError("Setting hash data failed");
  }
  if (aad.replace(hasher.DigestSize(), purpose_) !=
      kAdditionalAuthenticatedDataPurposeSize) {
    return absl::InternalError("Setting purpose data failed");
  }
  if (aad.replace(hasher.DigestSize() + kAdditionalAuthenticatedDataPurposeSize,
                  uuid_) != kAdditionalAuthenticatedDataUuidSize) {
    return absl::InternalError("Setting UUID data failed");
  }
  return aad;
}

}  // namespace asylo
