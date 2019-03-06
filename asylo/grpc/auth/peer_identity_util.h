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

#ifndef ASYLO_GRPC_AUTH_PEER_IDENTITY_UTIL_H_
#define ASYLO_GRPC_AUTH_PEER_IDENTITY_UTIL_H_

#include "asylo/grpc/auth/enclave_auth_context.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_expectation_matcher.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/impl/codegen/security/auth_context.h"

namespace asylo {

// Extracts the peer's SGX code identity from |context| and writes it into
// |code_identity|. If |context| does not represent an enclave authentication
// context, returns an internal error status. If there is no valid SGX code
// identity in |context|, returns a permission-denied status. Else, returns the
// result of parsing the identity from the enclave context. Errors from this
// function are suitable to return in an RPC.
Status ExtractAndCheckPeerSgxCodeIdentity(const ::grpc::AuthContext &context,
                                          sgx::CodeIdentity *code_identity);

// Extracts the peer's identity from |context| that matches
// |identity_expectation|.description(), and then compares it with
// |identity_expectation| using an appropriate matcher, if one is available. The
// user must link in the appropriate matcher libraries to their application. If
// there is no identity in |context| that matches
// |identity_expectation|.description(), returns a permission-denied status. If
// there is an error matching |identity_expectation|, returns an internal error.
// Else, returns whether or not the identity matches with the expectation.
// Errors from this function are suitable to return in an RPC.
StatusOr<bool> ExtractAndMatchEnclaveIdentity(
    const ::grpc::AuthContext &context,
    const EnclaveIdentityExpectation &identity_expectation);

// This overload is identical to the one above except that it instead uses
// |matcher| to match the peer's identities extracted from
// |enclave_auth_context| against |identity_expectation|.
StatusOr<bool> ExtractAndMatchEnclaveIdentity(
    const EnclaveAuthContext &enclave_auth_context,
    const EnclaveIdentityExpectation &identity_expectation,
    const IdentityExpectationMatcher &matcher);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_PEER_IDENTITY_UTIL_H_
