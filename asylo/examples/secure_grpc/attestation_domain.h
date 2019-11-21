/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_EXAMPLES_SECURE_GRPC_ATTESTATION_DOMAIN_H_
#define ASYLO_EXAMPLES_SECURE_GRPC_ATTESTATION_DOMAIN_H_

namespace examples {
namespace secure_grpc {

// Typically, the attestation domain value should be extracted from the system
// configuration (e.g., a file on the machine). For simplicity, it is hardcoded
// to the same value in the client and the server.
extern const char *const kAttestationDomain;

}  // namespace secure_grpc
}  // namespace examples

#endif  // ASYLO_EXAMPLES_SECURE_GRPC_ATTESTATION_DOMAIN_H_
