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

#include "absl/status/status.h"
#include "asylo/platform/posix/fork_security_test.pb.h"
#include "asylo/platform/primitives/sgx/fork_internal.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class ForkSecurityTest : public EnclaveTestCase {
 public:
  ForkSecurityTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!IsSecureForkSupported()) {
      return absl::UnavailableError(
          "Secure fork not supported in non SGX hardware mode");
    }
    if (!input.HasExtension(fork_security_test_input)) {
      return absl::InvalidArgumentError("Missing input extension");
    }
    ForkSecurityTestInput test_input =
        input.GetExtension(fork_security_test_input);
    if (!test_input.has_thread_type()) {
      return absl::InvalidArgumentError("Missing thread type");
    }
    if (test_input.thread_type() == ForkSecurityTestInput::SETREQUEST) {
      if (!test_input.has_request_fork()) {
        return absl::InvalidArgumentError("Missing request fork");
      }
      if (test_input.request_fork()) {
        SetForkRequested();
      }
      SaveThreadLayoutForSnapshot();
    } else if (test_input.thread_type() == ForkSecurityTestInput::WAIT) {
      if (!test_input.has_wait_thread_inside() ||
          test_input.wait_thread_inside() == 0) {
        return absl::InvalidArgumentError("Missing wait thread inside");
      }
      // Set the untrusted bit to inform the untrusted side the wait thread has
      // entered the enclave.
      volatile bool *wait_thread_inside =
          reinterpret_cast<bool *>(test_input.wait_thread_inside());
      *wait_thread_inside = true;
      // Stay inside the enclave until the untrusted side finished verifying and
      // reset the bit.
      while (*wait_thread_inside) {
      }
    } else {
      return absl::InvalidArgumentError("Unrecognized thread type");
    }
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new ForkSecurityTest; }

}  // namespace asylo
