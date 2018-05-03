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

#ifndef ASYLO_GRPC_AUTH_CORE_ENCLAVE_SECURITY_CONNECTOR_H_
#define ASYLO_GRPC_AUTH_CORE_ENCLAVE_SECURITY_CONNECTOR_H_

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/util/safe_string.h"
#include "src/core/lib/security/security_connector/security_connector.h"

/* --- Enclave security connectors. --- */

/* Creates an enclave channel security connector.
 *  |request_metadata_creds| is the call credentials object.
 *  |target| is the address of the server as a null-terminated std::string.
 *  |additional_authenticated_data| is additional data provided by the client
 *    and should be authenticated during the EKEP handshake.
 *  |aad_size| is the size of the data pointed to by
 *    |additional_authenticated_data|.
 *  |self_assertions| is a list of enclave identities possessed by the client.
 *  |accepted_peer_assertions| is a list of peer assertion accepted by the
 *    client. */
grpc_channel_security_connector *grpc_enclave_channel_security_connector_create(
    grpc_call_credentials *request_metadata_creds, const char *target,
    const safe_string *additional_authenticated_data,
    const assertion_description_array *self_assertions,
    const assertion_description_array *accepted_peer_assertions);

/* Creates an enclave server security connector.
 *  |additional_authenticated_data| is additional data provided by the server
 *    and should be authenticated during the EKEP handshake.
 *  |aad_size| is the size of the data pointed to by
 *    |additional_authenticated_data|.
 *  |self_assertions| is a list of enclave identities possessed by the server.
 *  |accepted_peer_assertions| is a list of peer assertions accepted by the
 *    server. */
grpc_server_security_connector *grpc_enclave_server_security_connector_create(
    const safe_string *additional_authenticated_data,
    const assertion_description_array *self_assertions,
    const assertion_description_array *accepted_peer_assertions);

#endif  // ASYLO_GRPC_AUTH_CORE_ENCLAVE_SECURITY_CONNECTOR_H_
