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
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "asylo/bazel/application_wrapper/application_wrapper.pb.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/fd_utils.h"
#include "asylo/util/status.h"

ABSL_FLAG(std::string, enclave_section, "",
          "The ELF section to load the enclave from");

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
    absl::StrAppend(&expected_stdout,
                    absl::StrJoin(environment_variables_, "\n",
                                  EnvironmentVariableFormatter()));
    if (!environment_variables_.empty()) {
      absl::StrAppend(&expected_stdout, "\n");
    }

    EnclaveOutput output;
    Status status = client_->EnterAndRun(EnclaveInput(), &output);
    CheckStdout(status.ok() ? expected_stdout : "", output);
    return status;
  }

 protected:
  // SetUpTestCase() configures and retrieves the enclave manager.
  static void SetUpTestSuite() {
    ASYLO_ASSERT_OK(EnclaveManager::Configure(EnclaveManagerOptions()));
    ASYLO_ASSERT_OK_AND_ASSIGN(manager_, EnclaveManager::Instance());
  }

  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_stdout_, Pipe::CreatePipe());
  }

  // Loads the enclave with the given command-line arguments and environment
  // variables, and directs its stdout into a pipe. Returns the Status returned
  // by manager_->LoadEnclave().
  Status LoadEnclave(std::vector<std::string> argv,
                     std::vector<std::pair<std::string, std::string>> envp) {
    // Save the command-line arguments and environment variables.
    args_ = std::move(argv);
    environment_variables_ = std::move(envp);

    // Create an EnclaveConfig that redirects the enclave's stdout and stderr
    // into the appropriate pipes and contains the command-line arguments.
    EnclaveConfig config;
    config.set_stdout_fd(enclave_stdout_.write_fd());
    CommandLineArgs *args = config.MutableExtension(command_line_args);
    for (const std::string &argument : args_) {
      args->add_arguments(argument);
    }
    for (const auto &pair : environment_variables_) {
      EnvironmentVariable *variable = config.add_environment_variables();
      variable->set_name(pair.first);
      variable->set_value(pair.second);
    }

    // Create an EnclaveLoadConfig object.
    EnclaveLoadConfig load_config;
    load_config.set_name(kEnclaveName);
    *load_config.mutable_config() = config;

    // Create an SgxLoadConfig object.
    SgxLoadConfig sgx_config;
    SgxLoadConfig::EmbeddedEnclaveConfig embedded_enclave_config;
    embedded_enclave_config.set_section_name(
        absl::GetFlag(FLAGS_enclave_section));
    *sgx_config.mutable_embedded_enclave_config() = embedded_enclave_config;
    sgx_config.set_debug(true);

    // Set an SGX message extension to load_config.
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    Status status = manager_->LoadEnclave(load_config);
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
    ASYLO_ASSERT_OK(enclave_stdout_.CloseWriteFd());
    ASYLO_ASSERT_OK_AND_ASSIGN(pipe_output, ReadAll(enclave_stdout_.read_fd()));

    // Check that the enclave's output to stdout matches |expected_stdout|.
    EXPECT_EQ(pipe_output, expected_stdout);

    // Check that the main_return_value extension is set to
    // args_.size().
    if (!expected_stdout.empty()) {
      ASSERT_TRUE(enclave_output.HasExtension(main_return_value));
      EXPECT_EQ(enclave_output.GetExtension(main_return_value), args_.size());
    }
  }

  struct EnvironmentVariableFormatter {
    void operator()(std::string *out,
                    std::pair<std::string, std::string> variable) {
      out->append(absl::StrCat(variable.first, "=\"", variable.second, "\""));
    }
  };

  std::vector<std::string> args_;
  std::vector<std::pair<std::string, std::string>> environment_variables_;
};

EnclaveManager *ApplicationWrapperEnclaveTest::manager_ = nullptr;

// Tests that ApplicationWrapperEnclave forwards 0 command-line arguments
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, NoArgs) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}, /*envp=*/{}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave forwards 1 command-line argument
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, OneArg) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{"foo"}, /*envp=*/{}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave forwards many command-line arguments
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, ManyArgs) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/
                              {"the", "quick", "brown", "fox", "jumps", "over",
                               "the", "lazy", "dog"},
                              /*envp=*/{}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave forwards the rest of the EnclaveConfig
// correctly.
TEST_F(ApplicationWrapperEnclaveTest, NoArgsAndEnvironmentVariables) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}, /*envp=*/{{"FOO", "foooo"}}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave forwards command-line arguments and the
// rest of the EnclaveConfig correctly.
TEST_F(ApplicationWrapperEnclaveTest, ManyArgsAndEnvironmentVariables) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/
                              {"the", "quick", "brown", "fox", "jumps", "over",
                               "the", "lazy", "dog"},
                              /*envp=*/{{"FOO", "foooo"}}));
  ASYLO_EXPECT_OK(RunEnclave());
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave returns an error from Initialize() if
// the EnclaveConfig does not have a command_line_args extension.
TEST_F(ApplicationWrapperEnclaveTest, NoArgsExtension) {
  SgxEmbeddedLoader loader(absl::GetFlag(FLAGS_enclave_section),
                           /*debug=*/true);
  EXPECT_THAT(
      manager_->LoadEnclave(kEnclaveName, loader),
      StatusIs(absl::StatusCode::kInvalidArgument,
               "Expected command_line_args extension on EnclaveConfig"));
}

// Tests that ApplicationWrapperEnclave does not allow the enclave application
// to run twice.
TEST_F(ApplicationWrapperEnclaveTest, NoMultipleRun) {
  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}, /*envp=*/{}));
  ASYLO_EXPECT_OK(RunEnclave());
  EXPECT_THAT(RunEnclave(), StatusIs(absl::StatusCode::kFailedPrecondition,
                                     "Application has already run"));
  ASYLO_EXPECT_OK(DestroyEnclave());
}

// Tests that ApplicationWrapperEnclave does not allow the enclave application
// to run multiple times, even if those runs are requested from multiple
// threads.
TEST_F(ApplicationWrapperEnclaveTest, NoMultipleRunFromMultipleThreads) {
  // The number of threads to use for the test.
  constexpr int kNumTestThreads = 256;

  // A phony Status used to initialize run_statuses so that if a thread does not
  // not update its corresponding entry in run_statuses, the un-updated Status
  // will not match the corresponding Status in expected_statuses.
  const Status phony_status(absl::StatusCode::kUnknown,
                            "Indicates that thread did not set this status");

  // The expected Statuses to be returned by each thread's call to RunEnclave(),
  // in no particular order.
  Matcher<const Status &> already_run_status_matcher = StatusIs(
      absl::StatusCode::kFailedPrecondition, "Application has already run");
  std::vector<Matcher<const Status &>> expected_statuses(
      kNumTestThreads - 1, already_run_status_matcher);
  expected_statuses.push_back(IsOk());

  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{}, /*envp=*/{}));

  // A vector to hold the statuses returned by each thread's call to
  // RunEnclave().
  std::vector<Status> run_statuses(kNumTestThreads, phony_status);

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

  ASYLO_ASSERT_OK(LoadEnclave(/*argv=*/{kTestApplicationName}, /*envp=*/{}));
  ASYLO_EXPECT_OK(DestroyEnclave());

  ASYLO_ASSERT_OK(enclave_stdout_.CloseWriteFd());
  EXPECT_THAT(ReadAll(enclave_stdout_.read_fd()),
              IsOkAndHolds(HasSubstr(absl::StrCat(
                  kTestApplicationName,
                  " enclave finalizing before application has run"))));
}

}  // namespace
}  // namespace asylo
