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

#ifndef ASYLO_GRPC_AUTH_UTIL_ENCLAVE_ASSERTION_UTIL_H_
#define ASYLO_GRPC_AUTH_UTIL_ENCLAVE_ASSERTION_UTIL_H_

#include <vector>

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/identity/identity.pb.h"

namespace asylo {

// Copies the list in |src| to a corresponding C structure in |dest|.
//
// This function is provided to bridge instances of the AssertionDescription
// proto to corresponding C structures. This is to enable passing information
// about assertions through the C-layer of gRPC.
void CopyAssertionDescriptions(
    const std::vector<AssertionDescription> &src,
    assertion_description_array *dest);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_UTIL_ENCLAVE_ASSERTION_UTIL_H_
