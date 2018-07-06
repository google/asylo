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

#include "asylo/identity/util/sha256_hash_util.h"

#include <string>

#include <google/protobuf/util/message_differencer.h>
#include "absl/strings/escaping.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/util/sha256_hash.pb.h"

namespace asylo {

bool Sha256HashFromHexString(const std::string &hex, Sha256HashProto *h) {
  UnsafeBytes<kSha256Size> bytes;

  if (!SetTrivialObjectFromHexString(hex, &bytes)) {
    return false;
  }

  h->set_hash(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  return true;
}

void Sha256HashToHexString(const Sha256HashProto &h, std::string *str) {
  *str = absl::BytesToHexString(h.hash());
}

bool operator==(const Sha256HashProto &left, const Sha256HashProto &right) {
  return ::google::protobuf::util::MessageDifferencer::Equivalent(left, right);
}

bool operator!=(const Sha256HashProto &left, const Sha256HashProto &right) {
  return !(left == right);
}

}  // namespace asylo
