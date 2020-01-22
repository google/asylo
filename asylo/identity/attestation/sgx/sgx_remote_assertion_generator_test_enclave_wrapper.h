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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_SGX_REMOTE_ASSERTION_GENERATOR_TEST_ENCLAVE_WRAPPER_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_SGX_REMOTE_ASSERTION_GENERATOR_TEST_ENCLAVE_WRAPPER_H_

#include <memory>
#include <string>

#include "asylo/client.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Wrapper class for the SgxRemoteAssertionGeneratorTestEnclave, allowing
// callers to interact with the enclave without making EnterAndRun calls.
class SgxRemoteAssertionGeneratorTestEnclaveWrapper {
 public:
  // Load the test enclave from |enclave_path|.
  static StatusOr<
      std::unique_ptr<SgxRemoteAssertionGeneratorTestEnclaveWrapper>>
  Load(asylo::EnclaveManager *enclave_manager, const std::string &enclave_path,
       sgx::SgxRemoteAssertionGeneratorTestEnclaveConfig test_enclave_config);

  SgxRemoteAssertionGeneratorTestEnclaveWrapper(EnclaveManager *enclave_manager,
                                                EnclaveClient *enclave_client);

  ~SgxRemoteAssertionGeneratorTestEnclaveWrapper();

  // Reset the assertion generator object held by the test enclave.
  Status ResetGenerator();

  // Returns the self identity of the test enclave.
  StatusOr<SgxIdentity> GetSgxSelfIdentity();

  // Returns |generator->IsInitialized()| from within the test enclave.
  StatusOr<bool> IsInitialized();

  // Returns |generator->Initialize(config)| from within the test enclave.
  Status Initialize(const std::string &config);

  // Returns |generator->CreateAssertionOffer()| from within the test enclave.
  StatusOr<AssertionOffer> CreateAssertionOffer();

  // Returns |generator->CreateGenerate(request)| from within the test enclave.
  StatusOr<bool> CanGenerate(AssertionRequest request);

  // Returns the assertion produced by calling |generator->Generate(user_data,
  // request)| from within the test enclave.
  StatusOr<Assertion> Generate(std::string user_data, AssertionRequest request);

 private:
  EnclaveManager *enclave_manager_;
  EnclaveClient *enclave_client_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_SGX_REMOTE_ASSERTION_GENERATOR_TEST_ENCLAVE_WRAPPER_H_
