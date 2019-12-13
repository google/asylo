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

#ifndef ASYLO_IDENTITY_ATTESTATION_NULL_INTERNAL_NULL_IDENTITY_CONSTANTS_H_
#define ASYLO_IDENTITY_ATTESTATION_NULL_INTERNAL_NULL_IDENTITY_CONSTANTS_H_

// This file defines various constants related to enclave null assertions.

namespace asylo {

// Authority responsible for generating and verifying null assertions.
extern const char *const kNullAssertionAuthority;

// Authority responsible for handling null identities.
extern const char *const kNullAuthorizationAuthority;

// Content of a null assertion.
extern const char *const kNullAssertion;

// Additional information presented in a null assertion offer.
extern const char *const kNullAssertionOfferAdditionalInfo;

// Additional information presented in a null assertion request.
extern const char *const kNullAssertionRequestAdditionalInfo;

// Identity extracted from a verified null assertion.
extern const char *const kNullIdentity;

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_NULL_INTERNAL_NULL_IDENTITY_CONSTANTS_H_
