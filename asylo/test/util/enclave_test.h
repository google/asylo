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

#ifndef ASYLO_TEST_UTIL_ENCLAVE_TEST_H_
#define ASYLO_TEST_UTIL_ENCLAVE_TEST_H_

#include <memory>
#include <string>

#include <gtest/gtest.h>
#include "absl/flags/declare.h"
#include "asylo/test/util/enclave_test_launcher.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/status.h"

ABSL_DECLARE_FLAG(std::string, enclave_path);

namespace asylo {

// Class that sets up enclave and exports a client pointer for individual tests
// to use.
class EnclaveTest : public ::testing::Test {
 public:
  void SetUp() override { SetUpBase(); }

  void TearDown() override { TearDownBase(); }

 protected:
  // Core of EnclaveTest setup. Any override should call this after preparing
  // config_.
  void SetUpBase();

  // Core of EnclaveTest teardown. Any override should call this after preparing
  // final_. Does not call EnterAndFinalize if |skip_finalize| is true.
  void TearDownBase(bool skip_finalize = false);

  // Specify the file descriptor to use for enclave stdin.
  void set_stdin(int fd) { config_.set_stdin_fd(fd); }

  // Specify the file descriptor to use for enclave stdout.
  void set_stdout(int fd) { config_.set_stdout_fd(fd); }

  // Specify the file descriptor to use for enclave stderr.
  void set_stderr(int fd) { config_.set_stderr_fd(fd); }

  // Creates a pipe for use in communicating with enclave stdin.
  // Returns writable end of pipe.
  int redirect_stdin();

  // Creates a pipe for use in communicating with enclave stdout.
  // Returns readable end of pipe.
  int redirect_stdout();

  // Creates a pipe for use in communicating with enclave stderr.
  // Returns readable end of pipe.
  int redirect_stderr();

  // Set a test string through enclave input protobuf extension field.
  void SetEnclaveInputTestString(EnclaveInput *enclave_input,
                                 const std::string &str_test) {
    EnclaveTestLauncher::SetEnclaveInputTestString(enclave_input, str_test);
  }

  // Get the test string from enclave output protobuf extension field.
  const std::string GetEnclaveOutputTestString(const EnclaveOutput &output) {
    return EnclaveTestLauncher::GetEnclaveOutputTestString(output);
  }

 protected:
  std::string enclave_url_;
  // An alias of |test_launcher_.client_| for more ergonomic use in test code.
  EnclaveClient *client_;
  EnclaveConfig config_;
  EnclaveTestLauncher test_launcher_;
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_ENCLAVE_TEST_H_
