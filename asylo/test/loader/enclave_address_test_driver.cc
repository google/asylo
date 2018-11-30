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

#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/client.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

DEFINE_string(enclave_path, "", "Path to enclave");

namespace asylo {
namespace {

class EnclaveAddressTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    if (!manager_result.ok()) {
      LOG(FATAL) << manager_result.status();
    }
    manager_ = manager_result.ValueOrDie();
    loader_ = absl::make_unique<SgxLoader>(FLAGS_enclave_path, /*debug=*/true);
  }

  EnclaveManager *manager_;
  std::unique_ptr<SgxLoader> loader_;
};

// Tests the enclave loading at specified address. First load an enclave, then
// fork the process, and load another enclave in the child process with the
// specified load address (same as the enclave address in the parent process),
// and verifies that the enclave loaded in the child process is in the same
// address.
TEST_F(EnclaveAddressTest, LoadEnclave) {
  std::string enclave_url = "/enclave_address";
  EnclaveConfig config;
  config.set_enable_fork(true);
  ASSERT_THAT(manager_->LoadEnclave(enclave_url, *loader_, config), IsOk());
  auto *parent_client =
      dynamic_cast<asylo::SgxClient *>(manager_->GetClient(enclave_url));
  void *parent_base_address = parent_client->base_address();
  ASSERT_NE(parent_base_address, nullptr);

  // Create a pipe between parent and  child process so that child process can
  // pass test result to the parent. This is needed because the test will pass
  // as long as the parent process passes, even if the child process
  // fails/crashes.
  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);

  SgxLoader *child_loader =
      dynamic_cast<SgxLoader *>(manager_->GetLoaderFromClient(parent_client));

  pid_t pid = fork();
  ASSERT_GE(pid, 0);

  if (pid == 0) {
    // Child process. Close the read side of the pipe and load a new enclave.
    close(pipefd[0]);
    std::string output = "Child test passed";
    std::string child_enclave_url = "/child_enclave_address";
    if (!manager_
             ->LoadEnclave(child_enclave_url, *child_loader, config,
                           parent_base_address)
             .ok()) {
      output = "Failed to load enclave in the child process";
    } else {
      auto *child_client =
          dynamic_cast<asylo::SgxClient *>(manager_->GetClient(enclave_url));
      void *child_base_address = child_client->base_address();
      if (child_base_address != parent_base_address) {
        output =
            "Enclave address loaded in the child process does not match the "
            "enclave in the parent enclave";
      }
    }
    // Write to pipe to let the parent process know the test result of the child
    // process.
    if (write(pipefd[1], output.c_str(), output.size()) == -1) {
      LOG(FATAL) << "Child process write to pipe failed";
    }
    _exit(0);
  } else {
    // Parent process. Close the write side of the pipe and wait for the result.
    close(pipefd[1]);
    int status;
    wait(&status);
    char buf[1024];
    int rc = read(pipefd[0], buf, sizeof(buf));
    EXPECT_GT(rc, 0);
    buf[rc] = '\0';
    EXPECT_STREQ(buf, "Child test passed");
  }
}

}  // namespace
}  // namespace asylo
