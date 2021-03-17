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

#include <unistd.h>

#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/test/misc/enclave_entry_count_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Enters the enclave and stays idle.
void EnterEnclave(EnclaveClient *client, const EnclaveInput &enclave_input) {
  EXPECT_THAT(client->EnterAndRun(enclave_input, /*output=*/nullptr), IsOk());
}

class EnclaveEntryCountTest : public EnclaveTest {
 protected:
  Status RunEnclaveEntryCountTest(int number_threads) {
    // Start threads that enters the enclave and leaves before count is
    // performed.
    EnclaveInput enclave_input;
    enclave_input.MutableExtension(enclave_entry_count_test_input)
        ->set_thread_type(EnclaveEntryCountTestInput::DONOTHING);
    std::vector<std::thread> entry_before_count_threads(number_threads);
    for (int i = 0; i < number_threads; ++i) {
      entry_before_count_threads[i] =
          std::thread(EnterEnclave, client_, enclave_input);
    }

    for (int i = 0; i < number_threads; ++i) {
      entry_before_count_threads[i].join();
    }

    // Start threads entering the enclave and wait, saving one for counting
    // threads.
    enclave_input.MutableExtension(enclave_entry_count_test_input)
        ->set_thread_type(EnclaveEntryCountTestInput::WAIT);
    std::vector<std::thread> entry_threads(number_threads - 1);
    for (int i = 0; i < number_threads - 1; ++i) {
      entry_threads[i] = std::thread(EnterEnclave, client_, enclave_input);
    }
    enclave_input.MutableExtension(enclave_entry_count_test_input)
        ->set_thread_type(EnclaveEntryCountTestInput::COUNT);
    enclave_input.MutableExtension(enclave_entry_count_test_input)
        ->set_expected_entries(number_threads);
    // Enters the enclave to count total enclave entries.
    EnclaveOutput enclave_output;
    Status status = client_->EnterAndRun(enclave_input, &enclave_output);
    if (!status.ok()) {
      return status;
    }
    for (int i = 0; i < number_threads - 1; ++i) {
      entry_threads[i].join();
    }
    if (enclave_output.GetExtension(number_entries) != number_threads) {
      return absl::InternalError("number of threads is incorrect");
    }
    return absl::OkStatus();
  }
};

// Test the enclave entry count is correct in single thread case.
TEST_F(EnclaveEntryCountTest, SingleThread) {
  constexpr int number_threads = 1;
  EXPECT_THAT(RunEnclaveEntryCountTest(number_threads), IsOk());
}

// Test the enclave entry count is correct in multithread case.
TEST_F(EnclaveEntryCountTest, MultiThread) {
  constexpr int number_threads = 8;
  EXPECT_THAT(RunEnclaveEntryCountTest(number_threads), IsOk());
}

}  // namespace
}  // namespace asylo
