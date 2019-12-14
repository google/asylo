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

#include "asylo/identity/attestation/null/null_identity_util.h"

#include "asylo/identity/attestation/null/internal/null_identity_constants.h"
#include "asylo/identity/descriptions.h"

namespace asylo {

EnclaveIdentityExpectation CreateNullIdentityExpectation() {
  EnclaveIdentityExpectation expectation;
  SetNullIdentityDescription(
      expectation.mutable_reference_identity()->mutable_description());
  expectation.mutable_reference_identity()->set_identity(kNullIdentity);
  // The match spec is not set because there are no additional fields to
  // compare.
  expectation.clear_match_spec();
  return expectation;
}

}  // namespace asylo
