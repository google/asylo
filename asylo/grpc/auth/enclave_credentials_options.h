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

#ifndef ASYLO_GRPC_AUTH_ENCLAVE_CREDENTIALS_OPTIONS_H_
#define ASYLO_GRPC_AUTH_ENCLAVE_CREDENTIALS_OPTIONS_H_

#include <string>
#include <vector>

#include "asylo/identity/identity.pb.h"

namespace asylo {

/// Options used to configure a `grpc::ChannelCredentials` object or a
/// `grpc::ServerCredentials` object for use in an enclave system.
struct EnclaveCredentialsOptions {
  /// Additional data that is authenticated during establishment of the gRPC
  /// channel. This string does not need to be null-terminated.
  std::string additional_authenticated_data;

  /// Assertions offered by the credential holder.
  std::vector<AssertionDescription> self_assertions;

  /// Peer assertions accepted by the credential holder.
  std::vector<AssertionDescription> accepted_peer_assertions;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_ENCLAVE_CREDENTIALS_OPTIONS_H_
