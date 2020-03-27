/*
 *
 * Copyright 2020 Asylo authors
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

#ifndef ASYLO_TEST_GRPC_CLIENT_SIDE_AUTH_TEST_CONSTANTS_H_
#define ASYLO_TEST_GRPC_CLIENT_SIDE_AUTH_TEST_CONSTANTS_H_

#include <cstdint>

#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Matches the client-side auth configuration in the BUILD file.
extern const uint32_t kClientSideAuthServerIsvprodid;
extern const uint32_t kClientSideAuthServerIsvsvn;

// Returns an SGX identity expectation that will match the identity for an
// enclave that uses the client-side auth test configuration and is signed with
// the Asylo debug key.
StatusOr<SgxIdentityExpectation> ClientSideAuthEnclaveSgxIdentityExpectation();

}  // namespace asylo
#endif  // ASYLO_TEST_GRPC_CLIENT_SIDE_AUTH_TEST_CONSTANTS_H_
