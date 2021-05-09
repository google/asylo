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

#ifndef ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_H_
#define ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_H_

#include <string>
#include <vector>

#include "absl/types/optional.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/credentials/credentials.h"

#define GRPC_CREDENTIALS_TYPE_ENCLAVE "Enclave"

/* -- Enclave credentials. -- */

struct grpc_enclave_channel_credentials final
    : public grpc_channel_credentials {
  // Creates a grpc_enclave_channel_credentials object using |options|. The
  // underlying object can be wrapped in a ::grpc::SecureChannelCredentials
  // object, which will handle its destruction.
  explicit grpc_enclave_channel_credentials(
      asylo::EnclaveCredentialsOptions options);

  grpc_core::RefCountedPtr<grpc_channel_security_connector>
  create_security_connector(
      grpc_core::RefCountedPtr<grpc_call_credentials> call_creds,
      const char* target, const grpc_channel_args* args,
      grpc_channel_args** new_args) override;

  // Additional authenticated data provided by the client.
  std::string additional_authenticated_data;

  // Assertions offered by the client.
  std::vector<asylo::AssertionDescription> self_assertions;

  // Server assertions accepted by the client.
  std::vector<asylo::AssertionDescription> accepted_peer_assertions;

  // Optional ACL enforced on the server's identity.
  absl::optional<asylo::IdentityAclPredicate> peer_acl;
};

struct grpc_enclave_server_credentials final : public grpc_server_credentials {
  // Creates a grpc_enclave_server_credentials object using |options|. The
  // underlying object can be wrapped in a ::grpc::SecureServerCredentials
  // object, which will handle its destruction.
  explicit grpc_enclave_server_credentials(
      asylo::EnclaveCredentialsOptions options);

  grpc_core::RefCountedPtr<grpc_server_security_connector>
  create_security_connector(const grpc_channel_args* /* args */) override;

  // Additional authenticated data provided by the server.
  std::string additional_authenticated_data;

  // Assertions offered by the server.
  std::vector<asylo::AssertionDescription> self_assertions;

  // Client assertions accepted by the server.
  std::vector<asylo::AssertionDescription> accepted_peer_assertions;

  // Optional ACL enforced on the client's identity.
  absl::optional<asylo::IdentityAclPredicate> peer_acl;
};

#endif  // ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_H_
