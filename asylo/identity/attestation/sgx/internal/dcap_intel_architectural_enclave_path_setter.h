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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_PATH_SETTER_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_PATH_SETTER_H_

#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

// Reads from the absl flag "intel_enclave_locations" and uses it to set the
// correct directory for Intel's DCAP library to load the architectural
// enclaves.
//
// This function is intended for test purposes, allowing tests to locate the
// Intel enclaves. This function is not thread safe.
Status SetIntelEnclaveDirFromFlags();

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_PATH_SETTER_H_
