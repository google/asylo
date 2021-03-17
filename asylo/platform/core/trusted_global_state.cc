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

#include "asylo/platform/core/trusted_global_state.h"

#include <string>

#include "absl/status/status.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Name of the enclave, as specified at the time the enclave was loaded.
static std::string *global_enclave_name = nullptr;

// Enclave configuration, as specified at the time the enclave was loaded.
static asylo::EnclaveConfig *global_enclave_config = nullptr;

void SetEnclaveName(const std::string &name) {
  delete global_enclave_name;
  global_enclave_name = new std::string(name);
}

const std::string &GetEnclaveName() { return *global_enclave_name; }

Status SetEnclaveConfig(const EnclaveConfig &config) {
  // EnclaveConfig may only be set once and additional calls will return an
  // error.
  if (global_enclave_config) {
    return absl::FailedPreconditionError("EnclaveConfig is already set");
  }
  global_enclave_config = new EnclaveConfig(config);
  return absl::OkStatus();
}

StatusOr<const EnclaveConfig *> GetEnclaveConfig() {
  if (!global_enclave_config) {
    return absl::FailedPreconditionError("EnclaveConfig is not set");
  }

  return global_enclave_config;
}

}  // namespace asylo
