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

#include "asylo/identity/attestation/null/null_identity_expectation_matcher.h"

#include <google/protobuf/util/message_differencer.h>
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/identity/attestation/null/null_identity_util.h"
#include "asylo/identity/descriptions.h"

namespace asylo {

StatusOr<bool> NullIdentityExpectationMatcher::MatchAndExplain(
    const EnclaveIdentity &identity,
    const EnclaveIdentityExpectation &expectation,
    std::string *explanation) const {
  // Make sure that the |identity| and the |expectation|.reference_identity()
  // have the correct description.
  const EnclaveIdentityDescription self_description = Description();
  const EnclaveIdentity &reference_identity = expectation.reference_identity();
  if (!::google::protobuf::util::MessageDifferencer::Equivalent(identity.description(),
                                                      self_description) ||
      !::google::protobuf::util::MessageDifferencer::Equivalent(
          reference_identity.description(), self_description)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Input parameter identity has incompatible description");
  }

  bool match = identity.identity() == reference_identity.identity();
  if (!match && explanation != nullptr) {
    *explanation = absl::StrFormat("%s does not match %s", identity.identity(),
                                   reference_identity.identity());
  }
  return match;
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
