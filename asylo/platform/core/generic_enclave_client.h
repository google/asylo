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

#ifndef ASYLO_PLATFORM_CORE_GENERIC_ENCLAVE_CLIENT_H_
#define ASYLO_PLATFORM_CORE_GENERIC_ENCLAVE_CLIENT_H_

#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/core/enclave_client.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/util/status.h"  // IWYU pragma: export

namespace asylo {

// Default implementation of EnclaveClient.
class GenericEnclaveClient : public EnclaveClient {
 public:
  static std::unique_ptr<GenericEnclaveClient> Create(
      const absl::string_view name,
      const std::shared_ptr<primitives::Client> primitive_client);

  Status EnterAndRun(const EnclaveInput &input, EnclaveOutput *output) override;

  std::shared_ptr<primitives::Client> GetPrimitiveClient() const {
    return primitive_client_;
  }

 protected:
  explicit GenericEnclaveClient(absl::string_view name)
      : EnclaveClient(name) {}

  // Primitive enclave client. Populated by the implementation of EnclaveLoader.
  std::shared_ptr<primitives::Client> primitive_client_;

 private:
  Status EnterAndInitialize(const EnclaveConfig &config) override;
  Status EnterAndFinalize(const EnclaveFinal &final_input) override;
  Status DestroyEnclave() override;

  // Enters the enclave and invokes the initialization entry-point. If the ecall
  // fails, or the enclave does not return any output, returns a non-OK status.
  // In this case, the caller cannot make any assumptions about the contents of
  // |output|. Otherwise, |output| points to a buffer of length *|output_len|
  // that contains output from the enclave.
  Status Initialize(const char *name, size_t name_len, const char *input,
                    size_t input_len, std::unique_ptr<char[]> *output,
                    size_t *output_len);

  // Enters the enclave and invokes the execution entry-point. If the ecall
  // fails, or the enclave does not return any output, returns a non-OK status.
  // In this case, the caller cannot make any assumptions about the contents of
  // |output|. Otherwise, |output| points to a buffer of length *|output_len|
  // that contains output from the enclave.
  Status Run(const char *input, size_t input_len,
             std::unique_ptr<char[]> *output, size_t *output_len);

  // Enters the enclave and invokes the finalization entry-point. If the ecall
  // fails, or the enclave does not return any output, returns a non-OK status.
  // In this case, the caller cannot make any assumptions about the contents of
  // |output|. Otherwise, |output| points to a buffer of length *|output_len|
  // that contains output from the enclave.
  Status Finalize(const char *input, size_t input_len,
                  std::unique_ptr<char[]> *output, size_t *output_len);

  void ReleaseMemory() override { primitive_client_->ReleaseMemory(); }
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_GENERIC_ENCLAVE_CLIENT_H_
