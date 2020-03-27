/*
 *
 * Copyright 2020 Asylo authors
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

#ifndef ASYLO_GRPC_AUTH_PEER_SGX_AGE_REMOTE_CREDENTIALS_OPTIONS_H_
#define ASYLO_GRPC_AUTH_PEER_SGX_AGE_REMOTE_CREDENTIALS_OPTIONS_H_

#include "asylo/grpc/auth/enclave_credentials_options.h"

namespace asylo {

/// Creates options suitable for configuring a credential used in establishing a
/// unidirectionally-authenticated gRPC channel where it accepts identities
/// attested by a remote SGX enclave using Asylo's Assertion Generator Enclave.
///
/// A credential configured with these options enforces that the peer
/// authenticates using SGX enclave code identity attested by Asylo's Assertion
/// Generator Enclave..
///
/// Sample usage for creating `::grpc::ChannelCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ChannelCredentials> creds =
///   EnclaveChannelCredentials(PeerSgxAgeRemoteCredentialsOptions());
/// ```
///
/// Sample usage for creating `::grpc::ServerCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ServerCredentials> creds =
///   EnclaveServerCredentials(PeerSgxAgeRemoteCredentialsOptions());
/// ```
///
/// \return Options used to configure gRPC credentials for a channel that is
///         unidirectionally-authenticated on the peer's end using
///         SGX enclave code identity.
EnclaveCredentialsOptions PeerSgxAgeRemoteCredentialsOptions();

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_PEER_SGX_AGE_REMOTE_CREDENTIALS_OPTIONS_H_
