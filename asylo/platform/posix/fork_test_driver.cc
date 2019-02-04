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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/client.h"
#include "gflags/gflags.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

DEFINE_string(enclave_path, "", "Path to enclave");

namespace asylo {
namespace {

class ForkTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    manager_ = manager_result.ValueOrDie();
    EnclaveConfig config;
    config.set_enable_fork(true);
    auto loader = absl::make_unique<SgxLoader>(FLAGS_enclave_path, true);
    ASSERT_THAT(manager_->LoadEnclave("/fork_test", *loader, config), IsOk());
    client_ = manager_->GetClient("/fork_test");
  }

  void TearDown() override {
    EXPECT_NE(client_, nullptr);
    EXPECT_NE(manager_, nullptr);
    EnclaveFinal efinal;
    EXPECT_THAT(manager_->DestroyEnclave(client_, efinal,
                                         /*skip_finalize=*/false), IsOk());
  }

  EnclaveManager *manager_;
  EnclaveClient *client_;
};

TEST_F(ForkTest, Fork) {
  EXPECT_THAT(client_->EnterAndRun({}, nullptr), IsOk());
}

}  // namespace
}  // namespace asylo
