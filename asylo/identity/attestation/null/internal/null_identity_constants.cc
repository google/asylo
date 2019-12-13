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

#include "asylo/identity/attestation/null/internal/null_identity_constants.h"

namespace asylo {

const char *const kNullAssertionAuthority = "Any";

const char *const kNullAuthorizationAuthority = kNullAssertionAuthority;

const char *const kNullAssertion = "EKEP Null Assertion";

const char *const kNullAssertionOfferAdditionalInfo =
    "EKEP Null Assertion Offer";

const char *const kNullAssertionRequestAdditionalInfo =
    "EKEP Null Assertion Request";

const char *const kNullIdentity = "Null Identity";

}  // namespace asylo
