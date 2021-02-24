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

class EnclaveProtoTest : public EnclaveTestCase {
 public:
  EnclaveProtoTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string buf = GetEnclaveInputTestString(input);
    EnclaveApiTest enclave_input_test;
    if (!enclave_input_test.ParseFromArray(buf.data(), buf.size())) {
      return absl::InvalidArgumentError(
          "Failed to deserialize string to enclave_input_test");
    }
    if (!enclave_input_test.has_test_string() ||
        !enclave_input_test.has_test_int() ||
        enclave_input_test.test_repeated_size() == 0) {
      return absl::InvalidArgumentError(
          "Field(s) of enclave_input_test not set");
    }
    if (enclave_input_test.test_string() != "test string" ||
        enclave_input_test.test_int() != 1 ||
        enclave_input_test.test_repeated_size() != 2 ||
        enclave_input_test.test_repeated(0) != "test repeated 1" ||
        enclave_input_test.test_repeated(1) != "test repeated 2") {
      return absl::InternalError(
          "Deserialized field(s) of enclave_input_test doesn't "
          "match the value set");
    }
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveProtoTest; }

}  // namespace asylo
