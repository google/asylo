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

#ifndef ASYLO_GRPC_AUTH_ENCLAVE_CHANNEL_CREDENTIALS_H_
#define ASYLO_GRPC_AUTH_ENCLAVE_CHANNEL_CREDENTIALS_H_

#include <memory>

#include "asylo/grpc/auth/core/enclave_credentials.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "include/grpcpp/security/credentials.h"

namespace asylo {

/// Constructs a `grpc::ChannelCredentials` object for use in an enclave system.
///
/// The configuration `options` determines which assertions are presented by the
/// entity that wields the resulting credentials object. `options` must meet the
/// following criteria:
///
///   * `options.self_assertions` must contain at least one assertion
///   description.
///   * `options.accepted_peer_assertions` must contain at least one assertion
///   description.
///
/// \param options Options for configuring the credentials.
/// \return A gRPC channel credentials object.
std::shared_ptr<::grpc::ChannelCredentials> EnclaveChannelCredentials(
    EnclaveCredentialsOptions options);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_ENCLAVE_CHANNEL_CREDENTIALS_H_
