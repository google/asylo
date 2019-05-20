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
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr int kAdditionalAuthenticatedDataSize = 64;

const char kGetPceInfoUuidHex[] = "00000000000000000000000000000000";
const char kGetPceInfoPurposeHex[] = "00000000000000000000000000000000";

const char kPceSignReportUuidHex[] = "4153594c4f205349474e5245504f5254";
const char kPceSignReportPurposeHex[] = "00000000000000000000000000000000";

const char kEkepUuidHex[] = "4153594c4f20454b4550000000000000";
const char kEkepPurposeHex[] = "00000000000000000000000000000000";

}  // namespace

AdditionalAuthenticatedDataGenerator::AdditionalAuthenticatedDataGenerator(
    UnsafeBytes<kAdditionalAuthenticatedDataUuidSize> uuid,
    UnsafeBytes<kAdditionalAuthenticatedDataPurposeSize> purpose)
    : uuid_(uuid), purpose_(purpose) {}

StatusOr<std::unique_ptr<AdditionalAuthenticatedDataGenerator>>
AdditionalAuthenticatedDataGenerator::CreateGetPceInfoAadGenerator() {
  UnsafeBytes<kAdditionalAuthenticatedDataUuidSize> uuid;
  ASYLO_RETURN_IF_ERROR(
      SetTrivialObjectFromHexString(kGetPceInfoUuidHex, &uuid));
  UnsafeBytes<kAdditionalAuthenticatedDataPurposeSize> purpose;
  ASYLO_RETURN_IF_ERROR(
      SetTrivialObjectFromHexString(kGetPceInfoPurposeHex, &purpose));
  return absl::make_unique<AdditionalAuthenticatedDataGenerator>(uuid, purpose);
}

StatusOr<std::unique_ptr<AdditionalAuthenticatedDataGenerator>>
AdditionalAuthenticatedDataGenerator::CreatePceSignReportAadGenerator() {
  UnsafeBytes<kAdditionalAuthenticatedDataUuidSize> uuid;
  ASYLO_RETURN_IF_ERROR(
      SetTrivialObjectFromHexString(kPceSignReportUuidHex, &uuid));
  UnsafeBytes<kAdditionalAuthenticatedDataPurposeSize> purpose;
  ASYLO_RETURN_IF_ERROR(
      SetTrivialObjectFromHexString(kPceSignReportPurposeHex, &purpose));
  return absl::make_unique<AdditionalAuthenticatedDataGenerator>(uuid, purpose);
}

StatusOr<std::unique_ptr<AdditionalAuthenticatedDataGenerator>>
AdditionalAuthenticatedDataGenerator::CreateEkepAadGenerator() {
  UnsafeBytes<kAdditionalAuthenticatedDataUuidSize> uuid;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromHexString(kEkepUuidHex, &uuid));
  UnsafeBytes<kAdditionalAuthenticatedDataPurposeSize> purpose;
  ASYLO_RETURN_IF_ERROR(
      SetTrivialObjectFromHexString(kEkepPurposeHex, &purpose));
  return absl::make_unique<AdditionalAuthenticatedDataGenerator>(uuid, purpose);
}

StatusOr<std::string> AdditionalAuthenticatedDataGenerator::Generate(
    absl::string_view data) {
  Sha256Hash hasher;
  hasher.Init();
  hasher.Update(data);
  std::vector<uint8_t> hash;
  ASYLO_RETURN_IF_ERROR(hasher.CumulativeHash(&hash));
  UnsafeBytes<kAdditionalAuthenticatedDataSize> aad;
  if (aad.replace(0, hash) != hasher.DigestSize()) {
    return Status(error::GoogleError::INTERNAL, "Setting hash data failed");
  }
  if (aad.replace(hasher.DigestSize(), purpose_) !=
      kAdditionalAuthenticatedDataPurposeSize) {
    return Status(error::GoogleError::INTERNAL, "Setting purpose data failed");
  }
  if (aad.replace(hasher.DigestSize() + kAdditionalAuthenticatedDataPurposeSize,
                  uuid_) != kAdditionalAuthenticatedDataUuidSize) {
    return Status(error::GoogleError::INTERNAL, "Setting UUID data failed");
  }
  return CopyToByteContainer<std::string>(aad);
}

}  // namespace asylo
