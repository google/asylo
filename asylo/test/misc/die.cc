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

#include <cstdlib>

#include "absl/status/status.h"
#include "asylo/trusted_application.h"
#include "include/sgx_trts.h"

namespace asylo {

class TestDie : public TrustedApplication {
 public:
  TestDie() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *) override {
    // We shouldn't be allowed inside crashed enclaves.
    if (sgx_is_enclave_crashed()) {
      return absl::InternalError("Enclave is crashed");
    }

    abort();
  }
};

TrustedApplication *BuildTrustedApplication() { return new TestDie; }

}  // namespace asylo
