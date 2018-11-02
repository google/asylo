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

#include "asylo/identity/named_identity_expectation_matcher.h"

#include <vector>

#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status_macros.h"

namespace asylo {

StatusOr<std::string> NamedIdentityExpectationMatcher::GetMatcherName(
    const EnclaveIdentityDescription &description) {
  std::string id;
  ASYLO_RETURN_IF_ERROR(SerializeByteContainers(
      &id, EnclaveIdentityType_Name(description.identity_type()),
      description.authority_type()));
  return id;
}

}  // namespace asylo
