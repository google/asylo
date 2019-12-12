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

#include "include/grpc/grpc_security.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/security_connector/security_connector.h"

/* --- Enclave security connectors. --- */

// Creates an enclave channel security connector.
// |channel_credentials| is the channel credentials object to use on the
// channel.
// |request_metadata_creds| is the call credentials object to use per call.
// |target| is the server endpoint to which to connect.
grpc_core::RefCountedPtr<grpc_channel_security_connector>
grpc_enclave_channel_security_connector_create(
    grpc_core::RefCountedPtr<grpc_channel_credentials> channel_credentials,
    grpc_core::RefCountedPtr<grpc_call_credentials> request_metadata_creds,
    const char *target);

// Creates an enclave server security connector.
// |server_credentials| is the server credentials object.
grpc_core::RefCountedPtr<grpc_server_security_connector>
grpc_enclave_server_security_connector_create(
    grpc_core::RefCountedPtr<grpc_server_credentials> server_credentials);

#endif  // ASYLO_GRPC_AUTH_CORE_ENCLAVE_SECURITY_CONNECTOR_H_
