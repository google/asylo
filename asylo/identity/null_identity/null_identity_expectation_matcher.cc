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

#include "asylo/identity/null_identity/null_identity_expectation_matcher.h"

#include <google/protobuf/util/message_differencer.h>
#include "asylo/identity/null_identity/null_identity_util.h"

namespace asylo {

StatusOr<bool> NullIdentityExpectationMatcher::Match(
    const EnclaveIdentity &identity,
    const EnclaveIdentityExpectation &expectation) const {
  // Make sure that the |identity| and the |expectation|.reference_identity()
  // have the correct description.
  EnclaveIdentityDescription self_description = Description();
  if (!::google::protobuf::util::MessageDifferencer::Equivalent(identity.description(),
                                                      self_description) ||
      !::google::protobuf::util::MessageDifferencer::Equivalent(
          expectation.reference_identity().description(), self_description)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Input parameter identity has incompatible description");
  }

  return identity.identity() == expectation.reference_identity().identity();
}

EnclaveIdentityDescription NullIdentityExpectationMatcher::Description() const {
  EnclaveIdentityDescription description;
  SetNullIdentityDescription(&description);
  return description;
}

// Static registration of the NullIdentityExpectationMatcher library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(IdentityExpectationMatcherMap,
                                     NullIdentityExpectationMatcher);

}  // namespace asylo
