/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SIM_UNTRUSTED_SIM_H_
#define ASYLO_PLATFORM_PRIMITIVES_SIM_UNTRUSTED_SIM_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "asylo/platform/primitives/sim/shared_sim.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/statusor.h"

// Simulated Enclave Untrusted Primitives
// ======================================
//
// The enclave simulator implements the Asylo primitives API inside a Unix
// process with no special security properties or guarantees.
//
// The simulator loads "trusted" code from a shared library object file with a
// call to dlopen(). The enclave library is expected to export "C" linkage
// symbols `asylo_enclave_init` and `asylo_enclave_fini` which will be called by
// the runtime to initialize and finalize the enclave respectively.

namespace asylo {
namespace primitives {

// Type signature of the enclave entry function pointer. All data extents in
// serialized `input` message are expected to be located in untrusted memory.
using EnclaveCallPtr = PrimitiveStatus (*)(uint64_t trusted_selector,
                                           const void *input, size_t input_size,
                                           void **output, size_t *output_size);

// Simulator implementation of the generic "EnclaveBackend" concept.
struct SimBackend {
  // Loads a simulation enclave from a file system path for the untrusted
  // application. Returns a client to the loaded enclave or an error status on
  // failure.
  static StatusOr<std::shared_ptr<Client>> Load(
      const absl::string_view enclave_name, const std::string &path,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider);
};

// Simulator implementation of Client.
class SimEnclaveClient : public Client {
 public:
  ~SimEnclaveClient() override;
  Status Destroy() override;
  Status EnclaveCallInternal(uint64_t selector, MessageWriter *input,
                             MessageReader *output) override;
  Status DeliverSignalInternal(
      MessageWriter *input, MessageReader *output) override;
  bool IsClosed() const override;

 private:
  // Allow the loader to create client instances directly.
  friend SimBackend;

  // Constructor.
  SimEnclaveClient(absl::string_view name,
                   std::unique_ptr<ExitCallProvider> exit_call_provider)
      : Client(name, std::move(exit_call_provider)) {}

  // Dynamic library handle for enclave instance loaded at runtime.
  void *dl_handle_ = nullptr;

  // Enclave entry point trampoline, performing a simulated context switch into
  // trusted execution mode and entering the enclave with a selector and message
  // buffers.
  EnclaveCallPtr enclave_call_ = nullptr;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SIM_UNTRUSTED_SIM_H_
