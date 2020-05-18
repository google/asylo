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

#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"

namespace asylo {
namespace sgx {

const char *const kSgxLocalAssertionAuthority = "SGX Local";

const char *const kSgxAgeRemoteAssertionAuthority = "SGX AGE";

const char *const kSgxIntelEcdsaQeRemoteAssertionAuthority =
    "SGX Intel ECDSA QE";

const char *const kSgxAuthorizationAuthority = "SGX";

const char *const kSgxIdentityVersionString = "SgxIdentity v0.1";

}  // namespace sgx
}  // namespace asylo
