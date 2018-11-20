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

#include <algorithm>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "asylo/bazel/application_wrapper/application_wrapper.pb.h"
#include "asylo/client.h"
#include "asylo/enclave_manager.h"
#include "gflags/gflags.h"
#include "asylo/test/util/pipe.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

DEFINE_string(enclave_section, "", "The ELF section to load the enclave from");

namespace asylo {
namespace {

using ::testing::HasSubstr;
using ::testing::Matcher;
using ::testing::UnorderedElementsAreArray;

// The enclave name to use for testing.
constexpr char kEnclaveName[] = "enclave";

// A text fixture for testing ApplicationWrapperEnclave.
class ApplicationWrapperEnclaveTest : public ::testing::Test {
 public:
  // Runs the application enclave. Returns the Status returned by
  // client_->EnterAndRun().
  //
  // If the EnterAndRun() call returns an OK status, RunWithArgs() checks that
  // the enclave prints each of its command-line arguments on a new line and
  // returns a main_return_value in the EnclaveOutput equal to the number of
  // command-line arguments given.
  Status RunEnclave() {
    std::string expected_stdout = absl::StrJoin(args_, "\n");
    if (!args_.empty()) {
      absl::StrAppend(&expected_stdout, "\n");
    }

    EnclaveOutput output;
    Status status = client_->EnterAndRun(EnclaveInput(), &output);
    CheckStdout(status.ok() ? expected_stdout : "", output);
    return status;
  }

 protected:
  // SetUpTestCase() configures and retrieves the enclave manager.
  static void SetUpTestCase() {
    EnclaveManager::Configure(EnclaveManagerOptions());
    ASYLO_ASSERT_OK_AND_ASSIGN(manager_, EnclaveManager::Instance());
  }

  // Loads the enclave with the given command-line arguments and directs its
  // stdout into a pipe. Returns the Status returned by manager_->LoadEnclave().
  Status LoadEnclave(std::vector<std::string> argv) {
    // Save the command-line arguments.
    args_ = std::move(argv);

    // Create an EnclaveConfig that redirects the enclave's stdout and stderr
    // into the appropriate pipes and contains the command-line arguments.
    EnclaveConfig config;
    config.set_stdout_fd(enclave_stdout_.write_fd());
    CommandLineArgs *args = config.MutableExtension(command_line_args);
    for (const std::string &argument : args_) {
      args->add_arguments(argument);
    }

    // Load the enclave.
    SgxEmbeddedLoader loader(FLAGS_enclave_section, /*debug=*/true);
    Status status = manager_->LoadEnclave(kEnclaveName, loader, config);

    if (status.ok()) {
      client_ = manager_->GetClient(kEnclaveName);
    }

    return status;
  }

  // Destroys the enclave. Returns the Status returned by
  // manager_->DestroyEnclave().
  Status DestroyEnclave() {
    return manager_->DestroyEnclave(client_, EnclaveFinal());
  }

  static EnclaveManager *manager_;

  EnclaveClient *client_;

  Pipe enclave_stdout_;

 private:
  // If |should_have_output| is true, checks that the enclave has written lines
  // of output to its stdout equal to |expected_stdout|, except with one extra
  // blank line at the end, and that the enclave has added a main_return_value
  // extension to |enclave_output| equal to expected_stdout.size().
  //
  // If |should_have_output| is false, instead checks that the enclave has not
  // written anything to its stdout.
  void CheckStdout(const std::string &expected_stdout,
                   const EnclaveOutput &enclave_output) {
    // Read the entirety of the enclave's stdout.
    std::string pipe_output;
    ASYLO_ASSERT_OK_AND_ASSIGN(pipe_output, enclave_stdout_.ReadUntilEof());

    // Check that the enclave's output to stdout matches |expected_stdout|.
    EXPECT_EQ(pipe_output, expected_stdout);

    // Check that the main_return_value extension is set to
    // expected_stdout->size().
    if (!expected_stdout.empty()) {
      ASSERT_TRUE(enclave_output.HasExtension(main_return_value));
      EXPECT_EQ(
          enclave_output.GetExtension(main_return_value),
          std::count(expected_stdout.begin(), expected_stdout.end(), '\n'));
    }
  }

  std::vector<std::string> args_;
};

EnclaveManager *ApplicationWrapperEnclaveTest::manager_ = nullptr;

// Tests that ApplicationWrapperEnclave forwards 0 command-line arguments
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, NoArgs) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave forwards 1 command-line argument
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, OneArg) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{"foo"}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave forwards many command-line arguments
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, ManyArgs) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/
                              {"the", "quick", "brown", "fox", "jumps", "over",
                               "the", "lazy", "dog"}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave returns an error from Initialize() if
// the EnclaveConfig does not have a command_line_args extension.
TEST_F(ApplicationWrapperEnclaveTest, NoArgsExtension) {
  SgxEmbeddedLoader loader(FLAGS_enclave_section, /*debug=*/true);
  EXPECT_THAT(
      manager_->LoadEnclave(kEnclaveName, loader),
      StatusIs(error::GoogleError::INVALID_ARGUMENT,
               "Expected command_line_args extension on EnclaveConfig"));
}

// Tests that ApplicationWrapperEnclave does not allow the enclave application
// to run twice.
TEST_F(ApplicationWrapperEnclaveTest, NoMultipleRun) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}));
  ASYLO_EXPECT_OK(RunEnclave());
  EXPECT_THAT(RunEnclave(), StatusIs(error::GoogleError::FAILED_PRECONDITION,
                                     "Application has already run"));
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave does not allow the enclave application
// to run multiple times, even if those runs are requested from multiple
// threads.
TEST_F(ApplicationWrapperEnclaveTest, NoMultipleRunFromMultipleThreads) {
  // The number of threads to use for the test.
  constexpr int kNumTestThreads = 256;

  // A dummy Status used to initialize run_statuses so that if a thread does not
  // not update its corresponding entry in run_statuses, the un-updated Status
  // will not match the corresponding Status in expected_statuses.
  const Status dummy_status(error::GoogleError::UNKNOWN,
                            "Indicates that thread did not set this status");

  // The expected Statuses to be returned by each thread's call to RunEnclave(),
  // in no particular order.
  Matcher<const Status &> already_run_status_matcher = StatusIs(
      error::GoogleError::FAILED_PRECONDITION, "Application has already run");
  std::vector<Matcher<const Status &>> expected_statuses(
      kNumTestThreads - 1, already_run_status_matcher);
  expected_statuses.push_back(IsOk());

  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}));

  // A vector to hold the statuses returned by each thread's call to
  // RunEnclave().
  std::vector<Status> run_statuses(kNumTestThreads, dummy_status);

  std::vector<std::thread> run_threads;
  run_threads.reserve(kNumTestThreads);
  for (int i = 0; i < kNumTestThreads; ++i) {
    run_threads.emplace_back(
        [i, &run_statuses](ApplicationWrapperEnclaveTest *test_fixture) {
          Status status = test_fixture->RunEnclave();
          run_statuses[i] = status;
        },
        this);
  }
  for (auto &thread : run_threads) {
    thread.join();
  }

  // Exactly one call to RunEnclave() should have returned an OK Status, while
  // the rest should have returned a FAILED_PRECONDITION Status.
  EXPECT_THAT(run_statuses, UnorderedElementsAreArray(expected_statuses));
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave logs a warning from Finalize() if the
// application has not run and that the warning message includes the debug
// application name given in the EnclaveConfig.
TEST_F(ApplicationWrapperEnclaveTest, FinalizeLogsWarningIfNoRun) {
  constexpr char kTestApplicationName[] = "Jean-Luc Picard";

  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{kTestApplicationName}));
  ASYLO_EXPECT_OK(DestroyEnclave());

  EXPECT_THAT(enclave_stdout_.ReadUntilEof(),
              IsOkAndHolds(HasSubstr(absl::StrCat(
                  kTestApplicationName,
                  " enclave finalizing before application has run"))));
}

}  // namespace
}  // namespace asylo
