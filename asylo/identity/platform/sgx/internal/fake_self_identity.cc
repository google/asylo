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

#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/self_identity_internal.h"

#ifdef __ASYLO__
#error "fake_self_identity.cc must not be linked inside an enclave."
#else

namespace asylo {
namespace sgx {

const SelfIdentity *GetSelfIdentity() {
  // Outside an SGX enclave, enclave identity is simulated by the FakeEnclave
  // object, and it can change from one call to this function to the next.
  // Consequently, the SelfIdentity object is populated anew on each call to
  // this function. Note that this part of the flow is only expected to be
  // invoked as a part of unit testing.
  static SelfIdentity *self_identity = new SelfIdentity();
  *self_identity = SelfIdentity();
  return self_identity;
}

}  // namespace sgx
}  // namespace asylo

#endif  // __ASYLO__
