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

#include "asylo/platform/arch/include/trusted/fork.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class ForkSecurityTest : public EnclaveTestCase {
 public:
  ForkSecurityTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!IsSecureForkSupported()) {
      return Status(error::GoogleError::UNAVAILABLE,
                    "Secure fork not supported in non SGX hardware mode");
    }
    SaveThreadLayoutForSnapshot();
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new ForkSecurityTest; }

}  // namespace asylo
