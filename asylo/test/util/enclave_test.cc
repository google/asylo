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

#include "asylo/test/util/enclave_test.h"

#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/enclave.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave");

namespace asylo {

void EnclaveTest::SetUpBase() {
  if (!absl::GetFlag(FLAGS_test_tmpdir).empty()) {
    LoggingConfig *logging_config = config_.mutable_logging_config();
    logging_config->set_log_directory(absl::GetFlag(FLAGS_test_tmpdir));
  }
  ASYLO_ASSERT_OK(test_launcher_.SetUp(absl::GetFlag(FLAGS_enclave_path),
                                       config_, enclave_url_));
  client_ = test_launcher_.mutable_client();
}

void EnclaveTest::TearDownBase(bool skip_finalize) {
  EnclaveFinal efinal;
  ASYLO_ASSERT_OK(test_launcher_.TearDown(efinal, skip_finalize));
}

int EnclaveTest::redirect_stdin() {
  int fds[2];
  CHECK_EQ(pipe(fds), 0);
  set_stdin(fds[0]);
  return fds[1];
}

int EnclaveTest::redirect_stdout() {
  int fds[2];
  CHECK_EQ(pipe(fds), 0);
  set_stdout(fds[1]);
  return fds[0];
}

int EnclaveTest::redirect_stderr() {
  int fds[2];
  CHECK_EQ(pipe(fds), 0);
  set_stderr(fds[1]);
  return fds[0];
}

}  // namespace asylo
