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

#include <fcntl.h>
#include <unistd.h>
#include <cstdio>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::StrEq;

// A test fixture is used because we need to set up the enclave
class PipeOutputTest : public EnclaveTest {
 public:
  void SetUp() override {
    // Create pipes for stdin, stdout, and stderr.
    int pair_stdin[2];
    int pair_stdout[2];
    int pair_stderr[2];

    CHECK_EQ(pipe(pair_stdin), 0);
    CHECK_EQ(pipe(pair_stdout), 0);
    CHECK_EQ(pipe(pair_stderr), 0);

    // Pass in the enclave side of the pair.
    set_stdin(pair_stdin[0]);
    set_stdout(pair_stdout[1]);
    set_stderr(pair_stderr[1]);

    // Wrap the host side as a FILE *.
    enclave_in_ = fdopen(pair_stdin[1], "w");
    enclave_out_ = fdopen(pair_stdout[0], "r");
    enclave_err_ = fdopen(pair_stderr[0], "r");

    SetUpBase();
  }

 protected:
  // The test driver end of the pipe as a FILE *.
  FILE *enclave_in_;
  FILE *enclave_out_;
  FILE *enclave_err_;
};

TEST_F(PipeOutputTest, WriteTest) {
  EnclaveInput enclave_input;

  // Write to enclave stdin.
  fputs("Hello from the driver!", enclave_in_);
  fclose(enclave_in_);

  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());

  char buf[1024];

  // Read from enclave stdout.
  ASSERT_NE(fgets(buf, sizeof(buf), enclave_out_), nullptr);
  EXPECT_THAT(buf, StrEq("Hello from enclave stdout!\n"));

  // Read from enclave stderr.
  ASSERT_NE(fgets(buf, sizeof(buf), enclave_err_), nullptr);
  EXPECT_THAT(buf, StrEq("Hello from enclave stderr!\n"));
}

}  // namespace
}  // namespace asylo
