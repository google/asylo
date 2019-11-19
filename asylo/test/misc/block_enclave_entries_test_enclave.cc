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

#include <errno.h>

#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/test/misc/block_enclave_entries_test.pb.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"

namespace asylo {

static bool check_thread_entered = false;

class BlockEnclaveEntriesTest : public EnclaveTestCase {
 public:
  BlockEnclaveEntriesTest() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!input.HasExtension(block_enclave_entries_test_input)) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Missing input extension");
    }
    BlockEnclaveEntriesTestInput test_input =
        input.GetExtension(block_enclave_entries_test_input);
    if (!test_input.has_thread_type()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Missing thread type");
    }

    if (test_input.thread_type() == BlockEnclaveEntriesTestInput::CHECK) {
      check_thread_entered = true;
      // Check thread only checks whether it can enter the enclave. Return
      // success since it reaches here.
      return Status::OkStatus();
    } else if (test_input.thread_type() ==
               BlockEnclaveEntriesTestInput::BLOCK) {
      if (!test_input.has_socket()) {
        return Status(error::GoogleError::INVALID_ARGUMENT,
                      "Missing thread type");
      }
      int socket = test_input.socket();

      if (blocked_entry_count() != 0) {
        return Status(error::GoogleError::INTERNAL,
                      "Found blocked entries while there shouldn't");
      }

      // Block entries and inform the untrusted thread to try entering the
      // enclave.
      enc_block_entries();
      std::string message = "Enclave entries blocked";
      if (enc_untrusted_write(socket, message.data(), message.size()) < 0) {
        return Status(static_cast<error::PosixError>(errno),
                      absl::StrCat("Write failed: ", strerror(errno)));
      }

      struct timespec ts;
      ts.tv_sec = 0;
      ts.tv_nsec = 100000000;

      // Wait till the enclave entry is blocked.
      while (blocked_entry_count() == 0) {
        nanosleep(&ts, /*rem=*/nullptr);
      }

      if (check_thread_entered) {
        return Status(error::GoogleError::INTERNAL,
                      "Enclave entries detected while blocked");
      }

      // Unblock entries and allow entry to enter the enclave.
      enc_unblock_entries();

      // Wait till the CHECK thread is unblocked and enters the enclave.
      while (!check_thread_entered) {
        nanosleep(&ts, /*rem=*/nullptr);
      }
    } else {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Unknown thread type");
    }

    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new BlockEnclaveEntriesTest;
}

}  // namespace asylo
