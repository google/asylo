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

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "asylo/platform/core/trusted_global_state.h"

#ifdef __ASYLO__
#error "fake_trusted_global_state.cc must not be linked inside an enclave"
#else  // __ASYLO__

namespace asylo {
namespace {

// Name of the enclave. This variable is made thread-local to simplify unit
// testing of certain identity libraries. The unit tests of those libraries
// emulate multiple enclaves in a single test, and switch the state associated
// with the enclave when they emulate enclave entry/exit. As different threads
// within the same process could be running different tests, making this
// variable thread-local allows those tests to proceed without contention.
ABSL_CONST_INIT thread_local std::string *enclave_name = nullptr;

// Enclave configuration. This variable is made thread-local to simplify unit
// testing of certain identity libraries.
ABSL_CONST_INIT thread_local asylo::EnclaveConfig *enclave_config = nullptr;

}  // namespace

void SetEnclaveName(const std::string &name) {
  delete enclave_name;
  enclave_name = new std::string(name);
}

const std::string &GetEnclaveName() { return *enclave_name; }

Status SetEnclaveConfig(const EnclaveConfig &config) {
  // The real SetEnclaveConfig implementation allows setting enclave config at
  // most once. However, the fake implementation allows setting it multiple
  // times to simplify unit testing of enclave-identity libraries, where in a
  // single test, we emulate multiple enclaves.
  delete enclave_config;
  enclave_config = new EnclaveConfig(config);
  return absl::OkStatus();
}

StatusOr<const EnclaveConfig *> GetEnclaveConfig() {
  if (!enclave_config) {
    return absl::FailedPreconditionError("EnclaveConfig is not set");
  }

  return enclave_config;
}

}  // namespace asylo

#endif  // __ASYLO__
