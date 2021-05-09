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

#include "asylo/grpc/auth/core/enclave_credentials.h"

#include <iterator>
#include <utility>

#include "asylo/grpc/auth/core/enclave_security_connector.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/credentials/credentials.h"

// Creates a grpc_enclave_channel_security_connector object.
grpc_core::RefCountedPtr<grpc_channel_security_connector>
grpc_enclave_channel_credentials::create_security_connector(
    grpc_core::RefCountedPtr<grpc_call_credentials> call_creds,
    const char *target, const grpc_channel_args *args,
    grpc_channel_args **new_args) {
  return grpc_enclave_channel_security_connector_create(
      this->Ref(), std::move(call_creds), target);
}

// Creates a grpc_enclave_server_security_connector object.
grpc_core::RefCountedPtr<grpc_server_security_connector>
grpc_enclave_server_credentials::create_security_connector(
    const grpc_channel_args * /* args */) {
  return grpc_enclave_server_security_connector_create(this->Ref());
}

grpc_enclave_channel_credentials::grpc_enclave_channel_credentials(
    asylo::EnclaveCredentialsOptions options)
    : grpc_channel_credentials(GRPC_CREDENTIALS_TYPE_ENCLAVE),
      additional_authenticated_data(
          std::move(options.additional_authenticated_data)),
      self_assertions(std::make_move_iterator(options.self_assertions.begin()),
                      std::make_move_iterator(options.self_assertions.end())),
      accepted_peer_assertions(
          std::make_move_iterator(options.accepted_peer_assertions.begin()),
          std::make_move_iterator(options.accepted_peer_assertions.end())),
      peer_acl(std::move(options.peer_acl)) {}

grpc_enclave_server_credentials::grpc_enclave_server_credentials(
    asylo::EnclaveCredentialsOptions options)
    : grpc_server_credentials(GRPC_CREDENTIALS_TYPE_ENCLAVE),
      additional_authenticated_data(
          std::move(options.additional_authenticated_data)),
      self_assertions(std::make_move_iterator(options.self_assertions.begin()),
                      std::make_move_iterator(options.self_assertions.end())),
      accepted_peer_assertions(
          std::make_move_iterator(options.accepted_peer_assertions.begin()),
          std::make_move_iterator(options.accepted_peer_assertions.end())),
      peer_acl(std::move(options.peer_acl)) {}
