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

#ifndef ASYLO_IDENTITY_NAMED_IDENTITY_EXPECTATION_MATCHER_H_
#define ASYLO_IDENTITY_NAMED_IDENTITY_EXPECTATION_MATCHER_H_

#include <string>

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_expectation_matcher.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// A `NamedIdentityExpectationMatcher` is capable of matching an identity to an
/// expectation if the identity and the expectation's reference identity have
/// the same identity descriptions, and they match the identity description
/// returned by the `Description()` method of the matcher. A
/// `NamedIdentityExpectationMatcher` is assigned a name based on the identity
/// description it handles. All subclasses of this class must be marked `final`.
class NamedIdentityExpectationMatcher : public IdentityExpectationMatcher {
 public:
  NamedIdentityExpectationMatcher() = default;

  // Mark the named identity expectation matcher as non-copyable and
  // non-movable.
  NamedIdentityExpectationMatcher(
      const NamedIdentityExpectationMatcher &other) = delete;
  NamedIdentityExpectationMatcher(NamedIdentityExpectationMatcher &&other) =
      delete;
  NamedIdentityExpectationMatcher &operator=(
      const NamedIdentityExpectationMatcher &other) = delete;
  NamedIdentityExpectationMatcher &operator=(
      NamedIdentityExpectationMatcher &&other) = delete;

  /// Returns the description of the enclave identities/enclave identity
  /// expectations this matcher is able to match. If the `MatchAndExplain()`
  /// method of this matcher is invoked with an identity or expectation with a
  /// different description, the matcher returns a non-OK status.
  ///
  /// \return A description of the enclave identities/enclave identity
  ///         expectations this matcher is able to match.
  virtual EnclaveIdentityDescription Description() const = 0;

  /// Converts `description` to a name that can be used as a unique identifier
  /// for a `NamedIdentityExpectationMatcher` that handles
  /// identities/expectations of this description.
  ///
  /// \param description The description to get a name for.
  /// \return A unique identifying string for `description`.
  static StatusOr<std::string> GetMatcherName(
      const EnclaveIdentityDescription &description);
};

template <>
struct Namer<NamedIdentityExpectationMatcher> {
  std::string operator()(const NamedIdentityExpectationMatcher &matcher) {
    return NamedIdentityExpectationMatcher::GetMatcherName(
               matcher.Description())
        .value();
  }
};

DEFINE_STATIC_MAP_OF_BASE_TYPE(IdentityExpectationMatcherMap,
                               NamedIdentityExpectationMatcher);

}  // namespace asylo

#endif  // ASYLO_IDENTITY_NAMED_IDENTITY_EXPECTATION_MATCHER_H_
