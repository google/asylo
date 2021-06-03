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

#include <string>

#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/test/util/status_matchers.h"

ABSL_FLAG(std::string, enclave_section, "",
          "The ELF section the enclave is located in");

namespace asylo {
namespace {

constexpr char kEnclaveName[] = "enclave";

TEST(EmbeddedEnclaveTest, EnclaveLoadsAndRuns) {
  // Retrieve the EnclaveManager.
  EnclaveManager::Configure(EnclaveManagerOptions());
  auto manager_result = EnclaveManager::Instance();
  ASSERT_THAT(manager_result, IsOk());
  EnclaveManager *manager = manager_result.value();

  // Create an EnclaveLoadConfig object.
  EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);
  EnclaveConfig config;
  *load_config.mutable_config() = config;

  // Create an SgxLoadConfig object.
  SgxLoadConfig sgx_config;
  SgxLoadConfig::EmbeddedEnclaveConfig embedded_enclave_config;
  embedded_enclave_config.set_section_name(
      absl::GetFlag(FLAGS_enclave_section));
  *sgx_config.mutable_embedded_enclave_config() = embedded_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(sgx_load_config) = sgx_config;

  ASSERT_THAT(manager->LoadEnclave(load_config), IsOk());
  EnclaveClient *client = manager->GetClient(kEnclaveName);

  // Enter the enclave with a no-op.
  EnclaveInput input;
  EnclaveOutput output;
  EXPECT_THAT(client->EnterAndRun(input, &output), IsOk());

  // Destroy the enclave.
  EnclaveFinal final_input;
  EXPECT_THAT(manager->DestroyEnclave(client, final_input), IsOk());
}

}  // namespace
}  // namespace asylo
