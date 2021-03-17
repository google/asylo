/*
 *
 * Copyright 2018 Asylo authors
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

#include <stdlib.h>

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/core/test/proto_test.pb.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status_macros.h"

namespace asylo {

class EnclaveGetenvTest : public EnclaveTestCase {
 public:
  EnclaveGetenvTest() = default;

  Status RunTest(const std::string &test_string) {
    const char *positive = strchr(test_string.c_str(), '=');
    if (positive) {
      std::string name(test_string.c_str(), positive - test_string.c_str());
      std::string value(positive + 1, test_string.size() - name.size() - 1);
      const char *test_value = getenv(name.c_str());
      if (!test_value) {
        return absl::InternalError(
            absl::StrCat("getenv returned null for name ", name));
      } else if (value != test_value) {
        return absl::InternalError(
            absl::StrCat("getenv returned an unexpected value for name ", name,
                         ": ", test_value, ", expected ", value));
      }
    } else {
      const char *negative = strchr(test_string.c_str(), '~');
      if (!negative) {
        return absl::InternalError(
            absl::StrCat("Bad test string: ", test_string));
      }
      std::string name(test_string.c_str(), negative - test_string.c_str());
      const char *negative_value = getenv(name.c_str());
      if (negative_value) {
        return absl::InternalError(
            absl::StrCat("Test for unset getenv returned a value for name ",
                         name, ": ", negative_value));
      }
    }
    return absl::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *) {
    std::string buf = GetEnclaveInputTestString(input);
    EnclaveApiTest enclave_input_test;
    if (!enclave_input_test.ParseFromArray(buf.data(), buf.size())) {
      return absl::InvalidArgumentError(
          "Failed to deserialize string to enclave_input_test");
    }
    if (enclave_input_test.test_repeated_size() != 2) {
      return absl::InternalError(
          "Deserialized field(s) of enclave_input_test doesn't "
          "match the value set");
    }
    for (const auto &test : enclave_input_test.test_repeated()) {
      ASYLO_RETURN_IF_ERROR(RunTest(test));
    }
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveGetenvTest; }

}  // namespace asylo
