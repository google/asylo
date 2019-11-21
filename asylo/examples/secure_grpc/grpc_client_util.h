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

#ifndef ASYLO_EXAMPLES_SECURE_GRPC_GRPC_CLIENT_UTIL_H_
#define ASYLO_EXAMPLES_SECURE_GRPC_GRPC_CLIENT_UTIL_H_

#include <string>

#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace examples {
namespace secure_grpc {

// Each of the following functions assume that the asylo::EnclaveManager
// instance has been configured using asylo::EnclaveManager::Configure().

// Loads the GrpcClientEnclave from |enclave_path|. If |debug_enclave| is true,
// loads the enclave in debug mode.
asylo::Status LoadGrpcClientEnclave(const std::string &enclave_path,
                                    bool debug_enclave);

// Makes the GrpcClientEnclave issue a GetTranslation RPC for
// |word_to_translate| to the server running at |address|, and returns the
// translated word on success. |channel_deadline| is the channel-establishment
// deadline. Returns a non-OK Status if the GrpcClientEnclave is not running.
asylo::StatusOr<std::string> GrpcClientEnclaveGetTranslation(
    const std::string &address, const std::string &word_to_translate);

// Destroys the GrpcClientEnclave and returns its finalization Status. Returns a
// non-OK Status if the GrpcClientEnclave is not running.
asylo::Status DestroyGrpcClientEnclave();

}  // namespace secure_grpc
}  // namespace examples

#endif  // ASYLO_EXAMPLES_SECURE_GRPC_GRPC_CLIENT_UTIL_H_
