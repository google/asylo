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

#include <string.h>

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/core/enclave_security_connector.h"
#include "asylo/grpc/auth/util/safe_string.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/credentials/credentials.h"

grpc_core::RefCountedPtr<grpc_channel_credentials>
grpc_enclave_channel_credentials_create(
    const grpc_enclave_credentials_options *options) {
  return grpc_core::MakeRefCounted<grpc_enclave_channel_credentials>(*options);
}

grpc_core::RefCountedPtr<grpc_server_credentials>
grpc_enclave_server_credentials_create(
    const grpc_enclave_credentials_options *options) {
  return grpc_core::MakeRefCounted<grpc_enclave_server_credentials>(*options);
}

// Frees any memory allocated by this channel credentials object.
grpc_enclave_channel_credentials::~grpc_enclave_channel_credentials() {
  safe_string_free(&additional_authenticated_data_);
  assertion_description_array_free(&self_assertions_);
  assertion_description_array_free(&accepted_peer_assertions_);
}

// Frees any memory allocated by this server credentials object.
grpc_enclave_server_credentials::~grpc_enclave_server_credentials() {
  safe_string_free(&additional_authenticated_data_);
  assertion_description_array_free(&self_assertions_);
  assertion_description_array_free(&accepted_peer_assertions_);
}

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
grpc_enclave_server_credentials::create_security_connector() {
  return grpc_enclave_server_security_connector_create(this->Ref());
}

grpc_enclave_channel_credentials::grpc_enclave_channel_credentials(
    const grpc_enclave_credentials_options &options)
    : grpc_channel_credentials(GRPC_CREDENTIALS_TYPE_ENCLAVE) {
  // Initialize all members.
  safe_string_init(&additional_authenticated_data_);
  assertion_description_array_init(/*count=*/0, &self_assertions_);
  assertion_description_array_init(/*count=*/0, &accepted_peer_assertions_);

  // Copy parameters.
  safe_string_copy(/*dest=*/&additional_authenticated_data_,
                   /*src=*/&options.additional_authenticated_data);
  assertion_description_array_copy(/*src=*/&options.self_assertions,
                                   /*dest=*/&self_assertions_);
  assertion_description_array_copy(
      /*src=*/&options.accepted_peer_assertions,
      /*dest=*/&accepted_peer_assertions_);
}

grpc_enclave_server_credentials::grpc_enclave_server_credentials(
    const grpc_enclave_credentials_options &options)
    : grpc_server_credentials(GRPC_CREDENTIALS_TYPE_ENCLAVE) {
  // Initialize all members.
  safe_string_init(&additional_authenticated_data_);
  assertion_description_array_init(/*count=*/0, &self_assertions_);
  assertion_description_array_init(/*count=*/0, &accepted_peer_assertions_);

  // Copy parameters.
  safe_string_copy(/*dest=*/&additional_authenticated_data_,
                   /*src=*/&options.additional_authenticated_data);
  assertion_description_array_copy(/*src=*/&options.self_assertions,
                                   /*dest=*/&self_assertions_);
  assertion_description_array_copy(
      /*src=*/&options.accepted_peer_assertions,
      /*dest=*/&accepted_peer_assertions_);
}
