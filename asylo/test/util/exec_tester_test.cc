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

#include "asylo/test/util/exec_tester.h"

#include <unistd.h>

#include <cstdlib>
#include <string>

#include <gtest/gtest.h>
#include "absl/flags/flag.h"

ABSL_FLAG(std::string, binary_path, "", "Path of the binary to execute");

namespace asylo {
namespace experimental {
namespace {

class ExecTesterTest : public ::testing::Test {
 public:
  void SetUp() override { app_ = absl::GetFlag(FLAGS_binary_path); }

 protected:
  class UniformOutputChecker : public ExecTester {
   public:
    UniformOutputChecker(const std::string &line,
                         const std::vector<std::string> &args, int minimum = 0,
                         bool hard_limit = true,
                         int fd_to_check = STDOUT_FILENO)
        : ExecTester(args, fd_to_check),
          line_(line),
          count_(0),
          minimum_(minimum),
          hard_limit_(hard_limit) {}

   protected:
    bool CheckLine(const std::string &line) override {
      bool check = (line == line_);
      if (check) ++count_;
      return (count_ >= minimum_) || check;
    }

    bool FinalCheck(bool accumulated) override {
      // Check that we've met or exceeded the minimum.
      // If a hard limit, we should exactly meet the minimum.
      if (!accumulated || !hard_limit_)
        return accumulated && count_ >= minimum_;
      return count_ == minimum_;
    }

   protected:
    std::string line_;
    int count_;
    int minimum_;
    bool hard_limit_;
  };

 protected:
  std::string app_;
};

TEST_F(ExecTesterTest, CheckExit3) {
  ExecTester run({app_, std::string("--exit3")});
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(3, WEXITSTATUS(status));
}

TEST_F(ExecTesterTest, CheckPrintA) {
  UniformOutputChecker run("A", {app_, std::string("--printA")}, 1);
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST_F(ExecTesterTest, CheckNoPrintB) {
  UniformOutputChecker run("B", {app_, std::string("--printA")}, 1, false);
  int status = 0;
  EXPECT_FALSE(run.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST_F(ExecTesterTest, CheckPrintB5) {
  UniformOutputChecker run("B", {app_, std::string("--printB5")}, 5);
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST_F(ExecTesterTest, CheckPrintB5Not3Times) {
  UniformOutputChecker run("B", {app_, std::string("--printB5")}, 3, false);
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST_F(ExecTesterTest, CheckSIGSEGV) {
  ExecTester run({app_, std::string("--segfault")});
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGSEGV, WTERMSIG(status));
}

TEST_F(ExecTesterTest, CheckSIGILL) {
  ExecTester run({app_, std::string("--sigill")});
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGILL, WTERMSIG(status));
}

TEST_F(ExecTesterTest, CheckStderrFoo) {
  UniformOutputChecker run("Foo", {app_, std::string("--stderrFoo")},
                           /*minimum=*/1,
                           /*hard_limit=*/true, /*fd_to_check=*/STDERR_FILENO);
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST_F(ExecTesterTest, CheckStdin) {
  UniformOutputChecker run("Lucky!", {app_, std::string("--stdin")}, 1);
  int status = 0;
  EXPECT_TRUE(run.Run("13\n", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

}  // namespace
}  // namespace experimental
}  // namespace asylo

