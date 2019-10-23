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

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "asylo/client.h"
#include "asylo/examples/remote/quickstart/demo.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"

ABSL_FLAG(std::string, enclave_path, "",
          "Path to enclave binary image to load");

using ::testing::IsEmpty;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::StrNe;

namespace asylo {
namespace {

constexpr char kEnclaveName[] = "DemoEnclave";

class DemoEnclaveRemoteTest : public ::testing::Test {
 public:
  void SetUp() override {
    const std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
    ASSERT_THAT(enclave_path, Not(IsEmpty()));

    EnclaveManager::Configure(EnclaveManagerOptions());
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_manager_, EnclaveManager::Instance());
    ASSERT_THAT(enclave_manager_, NotNull());

    std::unique_ptr<RemoteProxyClientConfig> proxy_config;
    ASYLO_ASSERT_OK_AND_ASSIGN(proxy_config,
                               RemoteProxyClientConfig::DefaultsWithProvision(
                                   RemoteProvision::Instantiate()));

    EnclaveLoadConfig load_config;
    load_config.set_name(kEnclaveName);

    auto remote_config = load_config.MutableExtension(remote_load_config);
    remote_config->set_remote_proxy_config(
        reinterpret_cast<uintptr_t>(proxy_config.release()));

    auto sgx_config = remote_config->mutable_sgx_load_config();
    sgx_config->set_debug(true);
    auto file_enclave_config = sgx_config->mutable_file_enclave_config();
    file_enclave_config->set_enclave_path(enclave_path);

    ASYLO_ASSERT_OK(enclave_manager_->LoadEnclave(load_config));
    enclave_client_ = enclave_manager_->GetClient(kEnclaveName);
    ASSERT_THAT(enclave_client_, NotNull());
  }

  void TearDown() override {
    EnclaveFinal empty_final_input;
    ASYLO_ASSERT_OK(enclave_manager_->DestroyEnclave(enclave_client_,
                                                     empty_final_input, false));
  }

 protected:
  EnclaveManager *enclave_manager_;
  EnclaveClient *enclave_client_;
};

TEST_F(DemoEnclaveRemoteTest, EnclaveEncryptsMessage) {
  constexpr char kMessage[] = "FooBar";
  EnclaveInput input;
  auto user_input = input.MutableExtension(guide::asylo::quickstart_input);
  user_input->set_value(kMessage);
  EnclaveOutput output;

  ASYLO_ASSERT_OK(enclave_client_->EnterAndRun(input, &output));
  ASSERT_THAT(output.HasExtension(guide::asylo::quickstart_output), IsTrue());
  const std::string encrypted_message =
      output.GetExtension(guide::asylo::quickstart_output).value();
  EXPECT_THAT(encrypted_message, Not(IsEmpty()));
  EXPECT_THAT(encrypted_message, StrNe(kMessage));
}

}  //  namespace
}  //  namespace asylo
