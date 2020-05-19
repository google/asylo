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

#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_authority_config.pb.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"

// The attestation domain is expected to be a 16-byte unique identifier.
constexpr char kAttestationDomain[] = "A 16-byte string";

extern "C" asylo::EnclaveConfig GetApplicationConfig() {
  asylo::EnclaveAssertionAuthorityConfig assertion_authority_config;
  asylo::SetSgxLocalAssertionDescription(
      assertion_authority_config.mutable_description());

  asylo::SgxLocalAssertionAuthorityConfig sgx_local_assertion_authority_config;
  sgx_local_assertion_authority_config.set_attestation_domain(
      kAttestationDomain);
  CHECK(sgx_local_assertion_authority_config.SerializeToString(
      assertion_authority_config.mutable_config()));

  asylo::EnclaveConfig enclave_config;
  *enclave_config.add_enclave_assertion_authority_configs() =
      std::move(assertion_authority_config);

  return enclave_config;
}
