/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_GRPC_AUTH_NULL_CREDENTIALS_OPTIONS_H_
#define ASYLO_GRPC_AUTH_NULL_CREDENTIALS_OPTIONS_H_

#include "asylo/grpc/auth/enclave_credentials_options.h"

namespace asylo {

/// Creates options suitable for configuring a credential used in establishing a
/// bidirectionally-unauthenticated gRPC channel between two enclave entities.
///
/// A credential configured with these options enforces bidirectional
/// authentication using the null identity. The null identity specifies no
/// identity in particular, which means that the resulting connection is
/// essentially unauthenticated.
///
/// Sample usage for creating `::grpc::ChannelCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ChannelCredentials> creds =
///   EnclaveChannelCredentials(BidirectionalNullCredentialsOptions());
/// ```
///
/// Sample usage for creating `::grpc::ServerCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ServerCredentials> creds =
///   EnclaveServerCredentials(BidirectionalNullCredentialsOptions());
/// ```
///
/// \return Options used to configure gRPC credentials for a
///         bidirectionally-unauthenticated channel.
EnclaveCredentialsOptions BidirectionalNullCredentialsOptions();

/// Creates options suitable for configuring a credential used in establishing a
/// unidirectionally-unauthenticated gRPC channel between two enclave entities.
///
/// A credential configured with these options enforces unidirectional
/// authentication using the null identity. The null identity specifies no
/// identity in particular, which means that in the resulting connection the
/// peer does not authenticate.
///
/// Sample usage for creating `::grpc::ChannelCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ChannelCredentials> creds =
///   EnclaveChannelCredentials(PeerNullCredentialsOptions());
/// ```
///
/// Sample usage for creating `::grpc::ServerCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ServerCredentials> creds =
///   EnclaveServerCredentials(PeerNullCredentialsOptions());
/// ```
///
/// \return Options used to configure gRPC credentials for a channel that is
///         unauthenticated on the peer's end.
EnclaveCredentialsOptions PeerNullCredentialsOptions();

/// Creates options suitable for configuring a credential used in establishing a
/// unidirectionally-unauthenticated gRPC channel between two enclave entities.
///
/// A credential configured with these options enforces unidirectional
/// authentication using the null identity. The null identity specifies no
/// identity in particular, which means that in the resulting connection
/// the credential holder does not authenticate.
///
/// Sample usage for creating `::grpc::ChannelCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ChannelCredentials> creds =
///   EnclaveChannelCredentials(SelfNullCredentialsOptions());
/// ```
///
/// Sample usage for creating `::grpc::ServerCredentials`:
///
/// ```
/// std::shared_ptr<::grpc::ServerCredentials> creds =
///   EnclaveServerCredentials(SelfNullCredentialsOptions());
/// ```
///
/// \return Options used to configure gRPC credentials for a channel that is
///         unauthenticated on the credential holder's end.
EnclaveCredentialsOptions SelfNullCredentialsOptions();

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_NULL_CREDENTIALS_OPTIONS_H_
