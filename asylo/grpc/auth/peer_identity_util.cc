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
#include "asylo/grpc/auth/peer_identity_util.h"

#include "asylo/grpc/auth/enclave_auth_context.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

Status ExtractAndCheckPeerSgxCodeIdentity(const ::grpc::ServerContext &context,
                                          sgx::CodeIdentity *code_identity) {
  StatusOr<EnclaveAuthContext> auth_context_result =
      EnclaveAuthContext::CreateFromServerContext(context);
  if (!auth_context_result.ok()) {
    LOG(ERROR) << "CreateFromServerContext failed: "
               << auth_context_result.status();
    return Status(error::GoogleError::INTERNAL,
                  "Failed to retrieve enclave authentication information");
  }

  EnclaveAuthContext auth_context = auth_context_result.ValueOrDie();
  EnclaveIdentityDescription code_identity_description;
  sgx::SetSgxIdentityDescription(&code_identity_description);
  StatusOr<const EnclaveIdentity *> identity_result =
      auth_context.FindEnclaveIdentity(code_identity_description);
  if (!identity_result.ok()) {
    LOG(ERROR) << "FindEnclaveIdentity failed: " << identity_result.status();
    return Status(error::GoogleError::PERMISSION_DENIED,
                  "Peer does not have SGX code identity");
  }
  return sgx::ParseSgxIdentity(*identity_result.ValueOrDie(), code_identity);
}

}  // namespace asylo
