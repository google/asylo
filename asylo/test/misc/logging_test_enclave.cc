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

#include <string.h>

#include <cfloat>
#include <climits>
#include <string>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {

class Logging : public EnclaveTestCase {
 public:
  Logging() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string which = GetEnclaveInputTestString(input);
    std::string empty_string = "";
    LOG(INFO) << "Test empty string" << empty_string;
    char test_char = 'c';
    LOG(INFO) << "Test logging " << test_char;
    char *test_null = nullptr;
    LOG(INFO) << "Test logging NULL" << test_null;
    std::string test_string = "string";
    LOG(INFO) << "Test logging " << test_string;
    char test_char_array[] = "char array";
    LOG(INFO) << "Test logging " << test_char_array;
    const char test_const_char_array[] = "const char array";
    LOG(INFO) << "Test logging " << test_const_char_array;
    LOG(INFO) << "Test logging int max " << INT_MAX;
    LOG(INFO) << "Test logging int min " << INT_MIN;
    LOG(INFO) << "Test logging long long max " << LLONG_MAX;
    LOG(INFO) << "Test logging long long min " << LLONG_MIN;
    LOG(INFO) << "Test logging float max " << FLT_MAX;
    LOG(INFO) << "Test logging float min " << FLT_MIN;
    LOG(INFO) << "Test logging double max " << DBL_MAX;
    LOG(INFO) << "Test logging double min " << DBL_MIN;
    LOG(WARNING) << "Test logging WARNING";
    LOG(ERROR) << "Test logging ERROR";
    LOG_IF(INFO, true) << "Test true conditional logging";
    LOG_IF(INFO, false) << "Test false conditional logging";
    VLOG(0) << "Test VLOG below level";
    VLOG(1) << "Test VLOG above level";
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new Logging; }

}  // namespace asylo
