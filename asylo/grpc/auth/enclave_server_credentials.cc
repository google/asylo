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

#include "asylo/grpc/auth/enclave_server_credentials.h"

#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/grpc/auth/util/enclave_assertion_util.h"
#include "asylo/grpc/auth/util/safe_string.h"
#include "src/cpp/server/secure_server_credentials.h"

namespace asylo {

std::shared_ptr<grpc::ServerCredentials> EnclaveServerCredentials(
    const EnclaveCredentialsOptions &options) {
  // Translate C++ options struct to C options struct.
  grpc_enclave_credentials_options c_opts;
  grpc_enclave_credentials_options_init(&c_opts);
  if (!options.additional_authenticated_data.empty()) {
    safe_string_assign(&c_opts.additional_authenticated_data,
                       options.additional_authenticated_data.size(),
                       options.additional_authenticated_data.data());
  }
  CopyAssertionDescriptions(options.self_assertions, &c_opts.self_assertions);
  CopyAssertionDescriptions(options.accepted_peer_assertions,
                            &c_opts.accepted_peer_assertions);

  // Create a server credentials objects using the options.
  auto creds = std::shared_ptr<grpc::ServerCredentials>(
      new grpc::SecureServerCredentials(
          grpc_enclave_server_credentials_create(&c_opts)));
  grpc_enclave_credentials_options_destroy(&c_opts);
  return creds;
}

}  // namespace asylo
