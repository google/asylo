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

#ifndef ASYLO_PLATFORM_ARCH_SGX_UNTRUSTED_SGX_CLIENT_H_
#define ASYLO_PLATFORM_ARCH_SGX_UNTRUSTED_SGX_CLIENT_H_

#include "asylo/platform/core/enclave_client.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/sgx_urts.h"

namespace asylo {

/// Enclave client for Intel Software Guard Extension (SGX) based enclaves.
class SGXClient : public EnclaveClient {
 public:
  explicit SGXClient(const std::string &name) : EnclaveClient(name) {}
  Status EnterAndRun(const EnclaveInput &input, EnclaveOutput *output) override;

  // Returns true when a TCS is active in simulation mode. Always returns false
  // in hardware mode, since TCS active/inactive state is only set and used in
  // simulation mode.
  bool IsTcsActive();

 private:
  friend class SGXLoader;
  SGXClient() = default;
  Status EnterAndInitialize(const EnclaveConfig &config) override;
  Status EnterAndFinalize(const EnclaveFinal &final_input) override;
  Status EnterAndDonateThread() override;
  Status EnterAndHandleSignal(const EnclaveSignal &signal) override;
  Status DestroyEnclave() override;
  std::string path_;               // Path to enclave object file.
  sgx_launch_token_t token_;  // SGX SDK launch token.
  sgx_enclave_id_t id_;       // SGX SDK enclave identifier.
};

/// Enclave loader for Intel Software Guard Extension (SGX) based enclaves.
class SGXLoader : public EnclaveLoader {
 public:
  /// Constructs an SGXLoader for an enclave object file on the file system,
  /// optionally in debug mode.
  ///
  /// \param path The path to the enclave binary (.so) file to load.
  /// \param debug Whether to load the enclave in debug mode.
  explicit SGXLoader(const std::string &path, bool debug)
      : path_(path), debug_(debug) {}

 private:
  const std::string path_;
  const bool debug_;
  StatusOr<std::unique_ptr<EnclaveClient>> LoadEnclave(
      const std::string &name) const override;
};

/// Enclave loader for simulated enclaves.
///
/// Enclave simulation currently uses the same binary format as SGX enclaves.
/// However, this is subject to change and consumers of this API should not
/// make assumptions about it being related to SGX.
using SimLoader = SGXLoader;

}  //  namespace asylo
#endif  // ASYLO_PLATFORM_ARCH_SGX_UNTRUSTED_SGX_CLIENT_H_
