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

#include "asylo/util/logging.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"

namespace asylo {

constexpr char kErrorString[] = "Secret error message";

// Test enclave that returns various errors over the enclave boundary.
class ErrorPropagationEnclave : public EnclaveTestCase {
 public:
  ErrorPropagationEnclave() = default;

  Status Initialize(const EnclaveConfig &config) final {
    return Status::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) final {
    std::string test_name = GetEnclaveInputTestString(input);

    if (test_name == "OK") {
      return Status::OkStatus();
    } else if (test_name == "error::GoogleError::UNAUTHENTICATED") {
      return Status(error::GoogleError::UNAUTHENTICATED, kErrorString);
    } else if (test_name == "error::PosixError::P_EINVAL") {
      return Status(error::PosixError::P_EINVAL, kErrorString);
    }

    LOG(ERROR) << "Unexpected test name: '" << test_name << "'";
    return Status(error::GoogleError::INTERNAL, "Unknown test");
  }

  Status Finalize(const EnclaveFinal &final_input) final {
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new ErrorPropagationEnclave();
}

}  // namespace asylo
