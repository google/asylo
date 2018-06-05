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

#include "asylo/grpc/auth/test/end2end_test_util.h"

#include <cstdint>

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/null_identity/null_identity_constants.h"

void set_null_assertion(assertion_description *description) {
  assertion_description_assign(
      static_cast<int32_t>(asylo::EnclaveIdentityType::NULL_IDENTITY),
      asylo::kNullAssertionAuthority, strlen(asylo::kNullAssertionAuthority),
      description);
}
