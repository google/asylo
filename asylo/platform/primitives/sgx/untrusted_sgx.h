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

#include <cstddef>
#include <memory>

#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/primitives/sgx/fork.pb.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/sgx_urts.h"

namespace asylo {
namespace primitives {

typedef Client *(*forked_loader_callback_t)(absl::string_view enclave_name,
                                            void *enclave_base_address,
                                            size_t enclave_size);

// Implementation of the generic "EnclaveBackend" concept for Intel Software
// Guard Extensions (SGX) based enclaves located in shared object files read
// from the file system.
struct SgxBackend {
  // Loads an SGX enclave and returns a client to the loaded enclave or an
  // error status on failure.
  static StatusOr<std::shared_ptr<Client>> Load(
      const absl::string_view enclave_name, void *base_address,
      absl::string_view enclave_path, size_t enclave_size,
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
      const absl::string_view enclave_name, void *base_address,
      absl::string_view section_name, size_t enclave_size,
      const EnclaveConfig &config, bool debug,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider);
};

// SGX implementation of Client.
class SgxEnclaveClient : public Client {
 public:
  ~SgxEnclaveClient() override;

  // Destroys an enclave. This method calls the user-defined
  // asylo_enclave_fini() entry point followed by marking the enclave for
  // destruction. Enclave destruction fails if the user defined enclave
  // finalization function fails.
  Status Destroy() override;

  // Registers exit handlers that are specific to SGX, for example, handler for
  // thread creation.
  Status RegisterExitHandlers() override;

  // Returns the sgx_enclave_id_t value of the underlying Intel SGX SDK enclave
  // resource.
  sgx_enclave_id_t GetEnclaveId() const;

  // Returns range of the virtual address space occupied by the loaded enclave.
  size_t GetEnclaveSize() const;

  // Returns the base address at which this enclave was loaded.
  void *GetBaseAddress() const;

  // Updates |token| with the SGX SDK launch token.
  void GetLaunchToken(sgx_launch_token_t *token) const;

  // Enters the enclave and invokes the snapshotting entry-point.
  Status EnterAndTakeSnapshot(SnapshotLayout *snapshot_layout);

  // Enters the enclave and invokes the restoring entry-point.
  Status EnterAndRestore(const SnapshotLayout &snapshot_layout);

  Status EnterAndTransferSecureSnapshotKey(
      const ForkHandshakeConfig &fork_handshake_config);

  int EnterAndHandleSignal(int signum, int sigcode);

  // Sets a new expected process ID for an existing SGX enclave.
  void SetProcessId();

  // Sets the callback function which loads a new child enclave based on the
  // parent when fork() is called.
  static void SetForkedEnclaveLoader(forked_loader_callback_t callback);

  // Gets the callback function which loads a new child enclave based on the
  // parent when fork() is called.
  static forked_loader_callback_t GetForkedEnclaveLoader();

 protected:
  Status EnclaveCallInternal(uint64_t selector, MessageWriter *input,
                             MessageReader *output) override;
  bool IsClosed() const override;

 private:
  friend SgxBackend;
  friend SgxEmbeddedBackend;

  // Constructor.
  SgxEnclaveClient(const absl::string_view name,
                   std::unique_ptr<ExitCallProvider> exit_call_provider)
      : Client(name, std::move(exit_call_provider)) {}

  sgx_launch_token_t token_ = {0};  // SGX SDK launch token.
  sgx_enclave_id_t id_;             // SGX SDK enclave identifier.
  void *base_address_;              // Enclave base address.
  size_t size_;                     // Enclave size.
  bool is_destroyed_ = true;        // Whether enclave is destroyed.
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_UNTRUSTED_SGX_H_
