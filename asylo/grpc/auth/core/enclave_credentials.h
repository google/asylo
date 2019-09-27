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

#include "absl/types/optional.h"
#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/core/enclave_credentials_options.h"
#include "asylo/grpc/auth/util/safe_string.h"
#include "asylo/identity/identity_acl.pb.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/credentials/credentials.h"

#define GRPC_CREDENTIALS_TYPE_ENCLAVE "Enclave"

/* -- Enclave credentials. -- */

// Creates a grpc_enclave_channel_credentials object using the provided options.
// The underlying object can be wrapped in a ::grpc::SecureChannelCredentials
// object, which will handle its destruction.
grpc_core::RefCountedPtr<grpc_channel_credentials>
grpc_enclave_channel_credentials_create(
    const grpc_enclave_credentials_options *options);

// Creates a grpc_enclave_server_credentials object using the provided options.
// The underlying object can be wrapped in a ::grpc::SecureServerCredentials
// object, which will handle its destruction.
grpc_core::RefCountedPtr<grpc_server_credentials>
grpc_enclave_server_credentials_create(
    const grpc_enclave_credentials_options* options);

class grpc_enclave_channel_credentials final : public grpc_channel_credentials {
 public:
  explicit grpc_enclave_channel_credentials(
      const grpc_enclave_credentials_options& options);
  ~grpc_enclave_channel_credentials() override;

  grpc_core::RefCountedPtr<grpc_channel_security_connector>
  create_security_connector(
      grpc_core::RefCountedPtr<grpc_call_credentials> call_creds,
      const char* target, const grpc_channel_args* args,
      grpc_channel_args** new_args) override;

  safe_string* mutable_additional_authenticated_data() {
    return &additional_authenticated_data_;
  }
  assertion_description_array* mutable_self_assertions() {
    return &self_assertions_;
  }
  assertion_description_array* mutable_accepted_peer_assertions() {
    return &accepted_peer_assertions_;
  }
  absl::optional<asylo::IdentityAclPredicate> peer_acl() { return peer_acl_; }

 private:
  // Additional authenticated data provided by the client.
  safe_string additional_authenticated_data_;

  // Assertions offered by the client.
  assertion_description_array self_assertions_;

  // Server assertions accepted by the client.
  assertion_description_array accepted_peer_assertions_;

  // Optional ACL enforced on the server's identity.
  absl::optional<asylo::IdentityAclPredicate> peer_acl_;
};

class grpc_enclave_server_credentials final : public grpc_server_credentials {
 public:
  explicit grpc_enclave_server_credentials(
      const grpc_enclave_credentials_options& options);
  ~grpc_enclave_server_credentials() override;

  grpc_core::RefCountedPtr<grpc_server_security_connector>
  create_security_connector() override;

  safe_string* mutable_additional_authenticated_data() {
    return &additional_authenticated_data_;
  }
  assertion_description_array* mutable_self_assertions() {
    return &self_assertions_;
  }
  assertion_description_array* mutable_accepted_peer_assertions() {
    return &accepted_peer_assertions_;
  }

  absl::optional<asylo::IdentityAclPredicate> peer_acl() { return peer_acl_; }

 private:
  // Additional authenticated data provided by the server.
  safe_string additional_authenticated_data_;

  // Assertions offered by the server.
  assertion_description_array self_assertions_;

  // Client assertions accepted by the server.
  assertion_description_array accepted_peer_assertions_;

  // Optional ACL enforced on the client's identity.
  absl::optional<asylo::IdentityAclPredicate> peer_acl_;
};

#endif  // ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_H_
