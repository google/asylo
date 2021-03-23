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

#include <sys/wait.h>
#include <unistd.h>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"

namespace asylo {

class ForkTest : public EnclaveTestCase {
 public:
  ForkTest() = default;
  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    // Create random variables on heap.
    char *test_heap = new char[10];
    for (int i = 0; i < 10; ++i) {
      test_heap[i] = '0' + i;
    }

    // Create a random variable on stack.
    char **test_stack = &test_heap;

    pid_t pid = fork();
    if (pid < 0) {
      abort();
    }
    if (pid == 0) {
      // Child enclave.
      // Verifies that variables on stack and heap are copied correctly. Abort
      // if not.
      for (int i = 0; i < 10; ++i) {
        if (test_heap[i] != '0' + i) {
          LOG(ERROR) << "Variable on heap in the child enclave does not match "
                        "expectation";
          abort();
        }
      }
      if (test_stack != &test_heap) {
        LOG(ERROR) << "Variable on stack in the child enclave does not match "
                      "expectation";
        abort();
      }

      _exit(0);
    } else {
      // Parent enclave.
      // Wait for the child enclave exits, and checks whether it exited
      // normally.
      int status;
      if (wait(&status) == -1) {
        return LastPosixError("Error waiting for child");
      }
      if (!WIFEXITED(status)) {
        return absl::InternalError("child enclave aborted");
      }
    }
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new ForkTest; }

}  // namespace asylo
