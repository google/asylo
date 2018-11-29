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

#ifndef ASYLO_PLATFORM_CORE_ENCLAVE_CLIENT_H_
#define ASYLO_PLATFORM_CORE_ENCLAVE_CLIENT_H_

#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/core/shared_name.h"
#include "asylo/util/status.h"  // IWYU pragma: export

namespace asylo {

/// An abstract enclave client.
///
/// A handle to an enclave object which provides methods for invoking its entry
/// points and managing its lifecycle.
class EnclaveClient {
 public:
  EnclaveClient(const EnclaveClient &) = delete;

  EnclaveClient &operator=(const EnclaveClient &) = delete;

  virtual ~EnclaveClient() = default;

  /// Enters the enclave and invokes its execution entry point.
  ///
  /// \param input A protobuf message that may be extended with a user-defined
  ///              message.
  /// \param[out] output A nullable pointer to a protobuf message that can store
  ///                    a response message.
  /// \anchor enter-and-run
  virtual Status EnterAndRun(const EnclaveInput &input,
                             EnclaveOutput *output) = 0;

 protected:
  /// Returns the name of the enclave.
  ///
  /// \return The name of the enclave.
  const std::string &get_name() const { return name_; }

  /// Called by the EnclaveManager to create a client instance.
  ///
  /// \param name The enclave name as registered with the EnclaveManager.
  explicit EnclaveClient(const std::string &name) : name_(name) {}

 private:
  friend class EnclaveManager;
  friend class EnclaveSignalDispatcher;
  friend void donate(EnclaveClient *client);

  // Enters the enclave and invokes its initialization entry point.
  virtual Status EnterAndInitialize(const EnclaveConfig &config) = 0;

  // Enters the enclave and invokes its finalization entry point.
  virtual Status EnterAndFinalize(const EnclaveFinal &final_input) = 0;

  // Donates the invoking thread to the enclave runtime.
  virtual Status EnterAndDonateThread() = 0;

  // Enters the enclave and invokes its signal handling entry point.
  virtual Status EnterAndHandleSignal(const EnclaveSignal &signal) = 0;

  // Enters the enclave and invokes its snapshotting entry point.
  virtual Status EnterAndTakeSnapshot(SnapshotLayout *snapshot_layout) = 0;

  // Enters the enclave and invokes its restoring entry point.
  virtual Status EnterAndRestore(const SnapshotLayout &snapshot_layout) = 0;

  // Invoked by the EnclaveManager immediately before the enclave is
  // destroyed. This hook is provided to enable execution of custom logic by the
  // client at the time the enclave is destroyed.
  virtual Status DestroyEnclave() = 0;

  std::string name_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ENCLAVE_CLIENT_H_
