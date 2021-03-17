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

#include "absl/status/status.h"
#include "asylo/test/util/enclave_test_application.h"

// These attributes attempt to forcibly create a global constructor/destructor.
static void start(void) __attribute__((constructor));
static void stop(void) __attribute__((destructor));

void start(void) { return; }

void stop(void) { return; }

namespace asylo {

class Initfini : public EnclaveTestCase {
 public:
  Initfini() = default;

  Status Initialize(const EnclaveConfig &config) { return absl::OkStatus(); }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    return absl::OkStatus();
  }

  Status Finalize(const EnclaveFinal &final_input) { return absl::OkStatus(); }
};

TrustedApplication *BuildTrustedApplication() { return new Initfini; }

}  // namespace asylo
