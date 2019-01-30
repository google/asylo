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

#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/util/status.h"
#include "include/grpcpp/impl/codegen/server_context.h"

namespace asylo {

// Extracts the peer's SGX code identity from |context| and writes it into
// |code_identity|. If |context| does not represent an enclave authentication
// context, returns an internal error status. If there is no valid SGX code
// identity in |context|, returns a permission-denied status. Else, returns the
// result of parsing the identity from the enclave context. Errors from this
// function are suitable to return in an RPC.
Status ExtractAndCheckPeerSgxCodeIdentity(const ::grpc::ServerContext &context,
                                          sgx::CodeIdentity *code_identity);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_PEER_IDENTITY_UTIL_H_
