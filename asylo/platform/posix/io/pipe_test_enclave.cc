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

#include <stdio.h>
#include <unistd.h>

#include "absl/status/status.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class PipeTest : public EnclaveTestCase {
 public:
  PipeTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    // Write test output back to the test driver.
    printf("Hello from enclave stdout!\n");
    fprintf(stderr, "Hello from enclave stderr!\n");

    // Close standard streams to indicate EOF.
    fclose(stdout);
    fclose(stderr);

    // Verify test input on stdin.
    char buf[1024];
    fgets(buf, sizeof(buf), stdin);
    if (strncmp(buf, "Hello from the driver!", sizeof(buf)) != 0) {
      return absl::InternalError("Read bad input from stdin");
    }

    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new PipeTest; }

}  // namespace asylo
