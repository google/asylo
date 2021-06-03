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

#include "asylo/identity/delegating_identity_expectation_matcher.h"

#include <google/protobuf/util/message_differencer.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/platform/common/static_map.h"

namespace asylo {

StatusOr<bool> DelegatingIdentityExpectationMatcher::MatchAndExplain(
    const EnclaveIdentity &identity,
    const EnclaveIdentityExpectation &expectation,
    std::string *explanation) const {
  // Find the appropriate matcher for |identity|.description() from the
  // IdentityExpectationMatcherMap.
  auto matcher_it = IdentityExpectationMatcherMap::GetValue(
      NamedIdentityExpectationMatcher::GetMatcherName(identity.description())
          .value());
  if (matcher_it == IdentityExpectationMatcherMap::value_end()) {
    return absl::InternalError(
        absl::StrCat("No matcher exists for identity with description ",
                     identity.description().ShortDebugString()));
  }

  // Make sure that the matcher is compatible with |expectation|.
  if (!::google::protobuf::util::MessageDifferencer::Equivalent(
          expectation.reference_identity().description(),
          identity.description())) {
    // Look up the description of |expectation| in the
    // IdentityExpectationMatcherMap. If a compatible matcher cannot be found,
    // then |expectation| is considered to have a description that is
    // unrecognized by this matcher.
    if (IdentityExpectationMatcherMap::GetValue(
            NamedIdentityExpectationMatcher::GetMatcherName(
                expectation.reference_identity().description())
                .value()) == IdentityExpectationMatcherMap::value_end()) {
      return absl::InternalError(absl::StrCat(
          "No matcher exists for matching expectation "
          "with reference-identity description ",
          expectation.reference_identity().description().ShortDebugString()));
    }

    // The matcher recognizes the descriptions of both |identity| and
    // |expectation|.reference_identity(), but they are different from each
    // other. Consequently, |identity| cannot possibly match |expectation|.
    //
    // This matcher may be used to compare an identity against multiple
    // expectations with differing reference-identity descriptions. Returning a
    // non-ok status here would break that comparison logic.
    if (explanation != nullptr) {
      *explanation = absl::StrFormat(
          "Matched identity, which has description %s, is incompatible with "
          "reference identity, which has description %s",
          identity.description().ShortDebugString(),
          expectation.reference_identity().description().ShortDebugString());
    }
    return false;
  }

  return matcher_it->MatchAndExplain(identity, expectation, explanation);
}

}  // namespace asylo
