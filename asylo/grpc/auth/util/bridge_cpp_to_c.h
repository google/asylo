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

#ifndef ASYLO_GRPC_AUTH_UTIL_BRIDGE_CPP_TO_C_H_
#define ASYLO_GRPC_AUTH_UTIL_BRIDGE_CPP_TO_C_H_

#include <vector>

#include "asylo/grpc/auth/core/enclave_credentials_options.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/identity/identity.pb.h"

namespace asylo {

// Copies the credentials options in |src| to a corresponding C structure in
// |dest|. The options structure in |dest| must have already been initialized.
//
// This function is provided for converting between EnclaveCredentialsOptions (a
// C++ structure) and grpc_enclave_credentials_options (an equivalent C
// structure). It enables passing information about credentials configuration
// from C++ layers of gRPC to C layers.
void CopyEnclaveCredentialsOptions(const EnclaveCredentialsOptions &src,
                                   grpc_enclave_credentials_options *dest);
}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_UTIL_BRIDGE_CPP_TO_C_H_
