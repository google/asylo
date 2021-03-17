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
#include "asylo/util/logging.h"
#include "asylo/platform/core/test/proto_test.pb.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class EnclaveApi : public EnclaveTestCase {
 public:
  EnclaveApi() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!input.HasExtension(enclave_api_test_input)) {
      return absl::InvalidArgumentError("Input extension not found");
    }
    EnclaveApiTest input_test = input.GetExtension(enclave_api_test_input);
    if (!input_test.has_test_string() || !input_test.has_test_int() ||
        input_test.test_repeated_size() == 0) {
      return absl::InvalidArgumentError("Field(s) of user_input not set");
    }
    if (input_test.test_string() != "test string" ||
        input_test.test_int() != 1 || input_test.test_repeated_size() != 2 ||
        input_test.test_repeated(0) != "test repeated 1" ||
        input_test.test_repeated(1) != "test repeated 2") {
      return absl::InvalidArgumentError(
          "Field(s) of user_input doesn't match the value set");
    }
    EnclaveApiTest output_test;
    output_test.set_test_string("output string");
    output_test.set_test_int(1);
    output_test.add_test_repeated("output repeated 1");
    output_test.add_test_repeated("output repeated 2");
    output->MutableExtension(enclave_api_test_output)->CopyFrom(output_test);

    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveApi; }

}  // namespace asylo
