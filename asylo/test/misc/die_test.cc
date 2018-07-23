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

#include <cstdlib>

#include <gtest/gtest.h>
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/exec_tester.h"

namespace asylo {
namespace {

class DieTest : public ::testing::Test {
 public:
  DieTest()
      : app_(experimental::ExecTester::BuildSiblingPath(
            FLAGS_enclave_path, "double_die_host_bin")) {}

 protected:
  std::string app_;
};

TEST_F(DieTest, TrapExits) {
  EXPECT_EXIT(__builtin_trap(), ::testing::KilledBySignal(SIGILL), ".*");
}

TEST_F(DieTest, HaltExits) {
  EXPECT_EXIT(asm("hlt"), ::testing::KilledBySignal(SIGSEGV), ".*");
}

TEST_F(DieTest, NoEntryAfterDie) {
  experimental::ExecTester run({app_, FLAGS_enclave_path});
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_FALSE(WIFSIGNALED(status)) << "Terminated by signal "
      << WTERMSIG(status);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(EXIT_FAILURE, WEXITSTATUS(status));
}

TEST_F(DieTest, CheckSIGILL) {
  experimental::ExecTester run({app_, std::string("--sigill")});
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_FALSE(WIFEXITED(status)) << "Terminated by exit, not signal: "
      << WEXITSTATUS(status);
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGILL, WTERMSIG(status));
}

TEST_F(DieTest, DieRaisesSIGILL) {
  experimental::ExecTester run({app_, FLAGS_enclave_path, std::string("--die")});
  int status = 0;
  EXPECT_TRUE(run.Run("", &status));
  EXPECT_FALSE(WIFEXITED(status)) << "Terminated by exit, not signal: "
      << WEXITSTATUS(status);
  ASSERT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGILL, WTERMSIG(status));
}

}  // namespace
}  // namespace asylo
