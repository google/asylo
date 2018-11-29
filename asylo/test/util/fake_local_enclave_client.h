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

#ifndef ASYLO_TEST_UTIL_FAKE_LOCAL_ENCLAVE_CLIENT_H_
#define ASYLO_TEST_UTIL_FAKE_LOCAL_ENCLAVE_CLIENT_H_

#include "asylo/client.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A FakeLocalEnclaveClient passes calls directly to an object that it holds.
// This object must implement the interface of the TrustedApplication. This
// class does not depend directly on TrustedApplication, since it is expected to
// be built with the native compiler, and TrustedApplication does not build with
// the native compiler.
template <typename EnclaveT>
class FakeLocalEnclaveClient : public EnclaveClient {
 public:
  explicit FakeLocalEnclaveClient(std::unique_ptr<EnclaveT> enclave)
      : EnclaveClient("fake local"), enclave_(std::move(enclave)) {}

  Status EnterAndRun(const EnclaveInput &input,
                     EnclaveOutput *output) override {
    return enclave_->Run(input, output);
  }

 private:
  Status EnterAndInitialize(const EnclaveConfig &config) override {
    return enclave_->Initialize(config);
  }

  Status EnterAndFinalize(const EnclaveFinal &final_input) override {
    return enclave_->Finalize(final_input);
  }

  Status EnterAndDonateThread() override { return Status::OkStatus(); }

  Status EnterAndHandleSignal(const EnclaveSignal &signal) override {
    return Status::OkStatus();
  }

  Status EnterAndTakeSnapshot(SnapshotLayout *snapshot_layout) override {
    return Status::OkStatus();
  }

  Status EnterAndRestore(const SnapshotLayout &snapshot_layout) override {
    return Status::OkStatus();
  }

  Status DestroyEnclave() override { return Status::OkStatus(); }

  // An enclave object that is owned by the client and handles all calls made to
  // the client.
  std::unique_ptr<EnclaveT> enclave_;
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_FAKE_LOCAL_ENCLAVE_CLIENT_H_
