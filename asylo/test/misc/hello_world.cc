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

#include <string>

#include "absl/status/status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class HelloWorld : public EnclaveTestCase {
 public:
  HelloWorld() = default;

  Status Initialize(const EnclaveConfig &config) {
    std::string str_config = GetEnclaveConfigTestString(config);
    primitives::TrustedPrimitives::DebugPuts(str_config.c_str());
    return absl::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string str_input = GetEnclaveInputTestString(input);
    primitives::TrustedPrimitives::DebugPuts(str_input.c_str());
    return absl::OkStatus();
  }

  Status Finalize(const EnclaveFinal &final_input) {
    std::string str_final = GetEnclaveFinalTestString(final_input);
    primitives::TrustedPrimitives::DebugPuts(str_final.c_str());
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new HelloWorld; }

}  // namespace asylo
