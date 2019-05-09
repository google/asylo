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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_

#include <string>

#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/util/statusor.h"
#include "include/sgx_urts.h"

namespace asylo {
namespace primitives {

// Implementation of the generic "EnclaveBackend" concept for Intel Software
// Guard Extensions (SGX) based enclaves located in shared object files read
// from the file system.
struct SgxBackend {
  // Loads an SGX enclave and returns a client to the loaded enclave or an
  // error status on failure.
  static StatusOr<std::shared_ptr<Client>> Load(
      void *base_address, absl::string_view enclave_path, size_t enclave_size,
      const EnclaveConfig &config, bool debug,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider);
};

// Implementation of the generic "EnclaveBackend" concept for Intel Software
// Guard Extensions (SGX) based enclaves embedded in the binary of the calling
// process.
struct SgxEmbeddedBackend {
  // Loads an embedded SGX enclave and returns a client to the loaded enclave or
  // an error status on failure.
  static StatusOr<std::shared_ptr<Client>> Load(
      void *base_address, absl::string_view section_name, size_t enclave_size,
      const EnclaveConfig &config, bool debug,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider);
};

// SGX implementation of Client.
class SgxEnclaveClient : public Client {
 public:
  ~SgxEnclaveClient() override;
  Status Destroy() override;

  // Returns the sgx_enclave_id_t value of the underlying Intel SGX SDK enclave
  // resource.
  sgx_enclave_id_t GetEnclaveId() const;

  // Returns range of the virtual address space occupied by the loaded enclave.
  size_t GetEnclaveSize() const;

  // Returns the base address at which this enclave was loaded.
  void *GetBaseAddress() const;

  // Updates |token| with the SGX SDK launch token.
  void GetLaunchToken(sgx_launch_token_t *token) const;

  // Calls the enclave initialization routine.
  Status Initialize(const char *enclave_name, const char *input,
                    size_t input_len, char **output, size_t *output_len);

 protected:
  Status EnclaveCallInternal(uint64_t selector,
                             UntrustedParameterStack *params) override;
  bool IsClosed() const override;

 private:
  friend SgxBackend;
  friend SgxEmbeddedBackend;

  // Constructor.
  explicit SgxEnclaveClient(
      std::unique_ptr<ExitCallProvider> exit_call_provider)
      : Client(std::move(exit_call_provider)) {}

  sgx_launch_token_t token_ = {0};  // SGX SDK launch token.
  sgx_enclave_id_t id_;             // SGX SDK enclave identifier.
  void *base_address_;              // Enclave base address.
  size_t size_;                     // Enclave size.
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_
