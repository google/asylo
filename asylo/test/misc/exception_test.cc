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

#include <signal.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/string_view.h"
#include "asylo/test/util/enclave_test.h"  // enclave_path
#include "asylo/test/util/exec_tester.h"

ABSL_FLAG(std::string, loader_path, "", "Path to loader binary");

namespace asylo {
namespace {

class ExceptionTest : public ::testing::Test {
 protected:
  // Return the status of the test subprocess.
  void RunTest(const std::string &input, int *status) {
    experimental::ExecTester test({
      absl::GetFlag(FLAGS_loader_path),
      absl::GetFlag(FLAGS_enclave_path), input});
    ASSERT_TRUE(test.Run("", status));
  }
};

TEST_F(ExceptionTest, Uncaught) {
  int status;
  ASSERT_NO_FATAL_FAILURE(RunTest("uncaught", &status));
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGILL, WTERMSIG(status));
}

TEST_F(ExceptionTest, Caught) {
  int status;
  ASSERT_NO_FATAL_FAILURE(RunTest("caught", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

}  // namespace
}  // namespace asylo
