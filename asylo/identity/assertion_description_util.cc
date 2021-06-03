/*
 *
 * Copyright 2018 Asylo authors
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

#include <functional>
#include <string>

#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/assertion_description_util.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

size_t AssertionDescriptionHasher::operator()(
    const AssertionDescription &description) const {
  return std::hash<std::string>()(
      SerializeAssertionDescription(description).value());
}

bool AssertionDescriptionEq::operator()(const AssertionDescription &lhs,
                                        const AssertionDescription &rhs) const {
  return lhs.identity_type() == rhs.identity_type() &&
         lhs.authority_type() == rhs.authority_type();
}

StatusOr<std::string> SerializeAssertionDescription(
    const AssertionDescription &description) {
  std::string serialized;
  ASYLO_RETURN_IF_ERROR(SerializeByteContainers(
      &serialized, EnclaveIdentityType_Name(description.identity_type()),
      description.authority_type()));
  return serialized;
}

}  // namespace asylo
