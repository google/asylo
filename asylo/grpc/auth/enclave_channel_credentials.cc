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

#include <memory>
#include <utility>

#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "include/grpcpp/security/credentials.h"
#include "src/cpp/client/secure_credentials.h"

namespace asylo {

std::shared_ptr<::grpc::ChannelCredentials> EnclaveChannelCredentials(
    EnclaveCredentialsOptions options) {
  // Create a channel credentials object using the options.
  return std::make_shared<::grpc::SecureChannelCredentials>(
      new grpc_enclave_channel_credentials(std::move(options)));
}

}  // namespace asylo
