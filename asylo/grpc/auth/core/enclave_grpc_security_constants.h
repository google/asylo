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

#ifndef ASYLO_GRPC_AUTH_CORE_ENCLAVE_GRPC_SECURITY_CONSTANTS_H_
#define ASYLO_GRPC_AUTH_CORE_ENCLAVE_GRPC_SECURITY_CONSTANTS_H_

// Enclave security authentication context property names.
#define GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME \
  "enclave_security.identity_proto"
#define GRPC_ENCLAVE_RECORD_PROTOCOL_PROPERTY_NAME \
  "enclave_security.record_protocol"

// Enclave transport security type. This is the auth context value for the
// GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME property.
#define GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE "enclave_security"

#endif  // ASYLO_GRPC_AUTH_CORE_ENCLAVE_GRPC_SECURITY_CONSTANTS_H_
