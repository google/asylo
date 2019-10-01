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
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kEnclaveName[] = "enclave";
constexpr char kClientName[] = "client";

TEST(FailFinalizeEnclaveTest, FailFinalize) {
  ASYLO_ASSERT_OK(EnclaveManager::Configure(EnclaveManagerOptions()));

  EnclaveManager *manager;
  ASYLO_ASSERT_OK_AND_ASSIGN(manager, EnclaveManager::Instance());

  // Create an EnclaveLoadConfig object.
  EnclaveLoadConfig load_config;
  load_config.set_name(kClientName);
  EnclaveConfig config;
  *load_config.mutable_config() = config;

  // Create an SgxLoadConfig object.
  SgxLoadConfig sgx_config;
  SgxLoadConfig::EmbeddedEnclaveConfig embedded_enclave_config;
  embedded_enclave_config.set_section_name(kEnclaveName);
  *sgx_config.mutable_embedded_enclave_config() = embedded_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(sgx_load_config) = sgx_config;

  ASYLO_ASSERT_OK(manager->LoadEnclave(load_config));

  auto client = manager->GetClient(kClientName);
  EnclaveFinal final_proto;
  EXPECT_THAT(manager->DestroyEnclave(client, final_proto), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
