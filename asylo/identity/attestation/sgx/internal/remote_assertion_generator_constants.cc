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

#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_constants.h"

namespace asylo {
namespace sgx {

const char *const kAttestationPublicKeyVersion =
    "Assertion Generator Enclave Attestation Key v0.1";
const char *const kAttestationPublicKeyPurpose =
    "Assertion Generator Enclave Attestation Key";
const char *const kPceSignReportPayloadVersion = "PCE Sign Report v0.1";

}  // namespace sgx
}  // namespace asylo
