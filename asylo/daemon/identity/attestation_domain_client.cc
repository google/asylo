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

#include "asylo/daemon/identity/attestation_domain_client.h"

#include <memory>

namespace asylo {
namespace daemon {

StatusOr<std::string> AttestationDomainClient::GetAttestationDomain() {
  ::grpc::ClientContext client_context;

  GetAttestationDomainRequest request;
  GetAttestationDomainResponse response;

  ::grpc::Status grpc_status =
      stub_->GetAttestationDomain(&client_context, request, &response);
  if (!grpc_status.ok()) {
    return Status(grpc_status);
  }

  return response.attestation_domain();
}

}  // namespace daemon
}  // namespace asylo
