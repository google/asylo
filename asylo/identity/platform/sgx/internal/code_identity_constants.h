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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_CODE_IDENTITY_CONSTANTS_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_CODE_IDENTITY_CONSTANTS_H_

namespace asylo {
namespace sgx {

// Constant representing the SGX local assertion authority type.
extern const char *const kSgxLocalAssertionAuthority;

// Constant representing the SGX AGE remote assertion authority type.
extern const char *const kSgxAgeRemoteAssertionAuthority;

// Constant representing Intel ECDSA assertion authority type.
extern const char *const kSgxIntelEcdsaQeRemoteAssertionAuthority;

// Constant representing SGX authorization authority type.
extern const char *const kSgxAuthorizationAuthority;

// Constant representing the version string of a serialized SGX identity
// in the |identity| field of an EnclaveIdentity.
extern const char *const kSgxIdentityVersionString;

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_CODE_IDENTITY_CONSTANTS_H_
