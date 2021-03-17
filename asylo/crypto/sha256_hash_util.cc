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

#include "asylo/crypto/sha256_hash_util.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {

constexpr uint32_t kSha256DigestLength = 32;

StatusOr<Sha256HashProto> CreateSha256HashProto(absl::string_view hash_hex) {
  UnsafeBytes<kSha256DigestLength> bytes;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromHexString(hash_hex, &bytes));

  Sha256HashProto hash;
  hash.set_hash(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  return hash;
}

Status ValidateSha256HashProto(const Sha256HashProto &hash_proto) {
  if (hash_proto.hash().size() != kSha256DigestLength) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("The length of the given hash (%d) does not match the "
                        "expected hash length for SHA-256 (%d)",
                        hash_proto.hash().size(), kSha256DigestLength));
  }
  return absl::OkStatus();
}

bool operator==(const Sha256HashProto &lhs, const Sha256HashProto &rhs) {
  return lhs.hash() == rhs.hash();
}

bool operator!=(const Sha256HashProto &lhs, const Sha256HashProto &rhs) {
  return !(lhs == rhs);
}

}  // namespace asylo
