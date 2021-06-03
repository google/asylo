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

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave");

namespace asylo {
namespace {

class ForkTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    manager_ = manager_result.value();
    EnclaveConfig config;
    *config.add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();
    config.set_enable_fork(true);

    // Prepare |load_config| message.
    EnclaveLoadConfig load_config;
    load_config.set_name("/fork_test");
    *load_config.mutable_config() = config;
    SgxLoadConfig sgx_config;
    SgxLoadConfig::FileEnclaveConfig file_enclave_config;
    file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
    *sgx_config.mutable_file_enclave_config() = file_enclave_config;
    sgx_config.set_debug(true);
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    // Load Enclave with prepared |EnclaveManager| and |load_config| message.
    asylo::EnclaveManager *manager = manager_result.value();
    ASSERT_THAT(manager->LoadEnclave(load_config), IsOk());

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
