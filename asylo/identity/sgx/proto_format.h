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

#ifndef ASYLO_IDENTITY_SGX_PROTO_FORMAT_H_
#define ASYLO_IDENTITY_SGX_PROTO_FORMAT_H_

#include <string>

#include "asylo/identity/sgx/code_identity.pb.h"

namespace asylo {
namespace sgx {

// For each of the supported proto types, returns a formatted string containing
// a human-understandable representation of the given proto. The string is the
// same as the one returned by Message::DebugString(), but with the following
// changes to improve readability:
//   * All bytes fields are hex-encoded.
//   * All BitVector128 fields that are representations of ATTRIBUTES are
//   printed as a list of ATTRIBUTE bit names.

std::string FormatCodeIdentityProto(const CodeIdentity &code_identity);

std::string FormatCodeIdentityMatchSpecProto(
    const CodeIdentityMatchSpec &match_spec);

std::string FormatCodeIdentityExpectationProto(
    const CodeIdentityExpectation &expectation);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_PROTO_FORMAT_H_
