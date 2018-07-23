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

#include "asylo/grpc/auth/enclave_channel_credentials.h"

#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/grpc/auth/util/bridge_cpp_to_c.h"
#include "src/cpp/client/secure_credentials.h"

namespace asylo {

std::shared_ptr<::grpc::ChannelCredentials> EnclaveChannelCredentials(
    const EnclaveCredentialsOptions &options) {
  // Translate C++ options struct to C options struct.
  grpc_enclave_credentials_options c_opts;
  grpc_enclave_credentials_options_init(&c_opts);
  CopyEnclaveCredentialsOptions(options, &c_opts);

  // Create a channel credentials object using the options.
  auto creds = std::shared_ptr<::grpc::ChannelCredentials>(
      new ::grpc::SecureChannelCredentials(
          grpc_enclave_channel_credentials_create(&c_opts)));
  grpc_enclave_credentials_options_destroy(&c_opts);
  return creds;
}

}  // namespace asylo
