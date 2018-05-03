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

#ifndef ASYLO_IDENTITY_IDENTITY_EXPECTATION_MATCHER_H_
#define ASYLO_IDENTITY_IDENTITY_EXPECTATION_MATCHER_H_

#include "asylo/identity/identity.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {

// IdentityExpectationMatcher defines an abstract interface that describes how
// to match an EnclaveIdentity against an EnclaveIdentityExpectation.
class IdentityExpectationMatcher {
 public:
  IdentityExpectationMatcher() = default;
  virtual ~IdentityExpectationMatcher() = default;

  // Evaluates whether |identity| matches |expectation|. Returns false if
  // |identity| does not match |expectation|. Returns a non-ok status if the
  // matcher does not understand either |identity| or |expectation|. This can
  // happen if:
  //  1. |identity|.description() is unrecognized by the matcher
  //  2. |expectation|.reference_identity().description() is unrecognized by the
  //     matcher
  //  3. |identity| and/or |expectation| is malformed
  //
  // It is up to the caller of this method to ensure that this method is called
  // with parameters recognized by the matcher. All implementations of this
  // function are expected to be thread-safe.
  virtual StatusOr<bool> Match(
      const EnclaveIdentity &identity,
      const EnclaveIdentityExpectation &expectation) const = 0;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_IDENTITY_EXPECTATION_MATCHER_H_
