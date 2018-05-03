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

#include <errno.h>
#include <memory>
#include <string>

#include "grpcpp/security/server_credentials.h"
#include "absl/memory/memory.h"
#include "asylo/grpc/auth/enclave_server_credentials.h"
#include "asylo/grpc/util/enclave_server.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/null_identity/null_identity_constants.h"
#include "asylo/test/grpc/messenger_server_impl.h"

namespace asylo {
namespace {

void SetNullAssertionDescription(AssertionDescription *assertion_description) {
  assertion_description->set_identity_type(EnclaveIdentityType::NULL_IDENTITY);
  assertion_description->set_authority_type(kNullAssertionAuthority);
}

std::shared_ptr<::grpc::ServerCredentials> GetServerCredentials() {
  // Set configurations options for the server's credentials:
  //   * Server offers the null assertion
  //   * Server accepts the null assertion
  EnclaveCredentialsOptions options;
  options.self_assertions.emplace_back();
  SetNullAssertionDescription(&options.self_assertions.back());
  options.accepted_peer_assertions.emplace_back();
  SetNullAssertionDescription(&options.accepted_peer_assertions.back());

  // Create an EnclaveServerCredentials object to configure the underlying
  // security mechanism for the server.
  return asylo::EnclaveServerCredentials(options);
}

}  // namespace

// Creates an enclave application hosting a simple gRPC server with EKEP null
// credentials.
TrustedApplication *BuildTrustedApplication() {
  return new EnclaveServer<test::MessengerServer1>(
      absl::make_unique<test::MessengerServer1>(), GetServerCredentials());
}

}  // namespace asylo
