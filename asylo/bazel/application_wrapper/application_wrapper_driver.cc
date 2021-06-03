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

#include "asylo/bazel/application_wrapper/application_wrapper_driver_main.h"
#include "asylo/client.h"
#include "asylo/enclave_manager.h"
#include "asylo/util/logging.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// The name of the ELF section to find the application enclave in.
constexpr char kSectionName[] = "enclave";

// The name to use for the whole-application wrapper enclave.
constexpr char kEnclaveName[] = "application_enclave";

}  // namespace
}  // namespace asylo

int main(int argc, char *argv[]) {
  // Configure the EnclaveManager.
  asylo::Status status =
      asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  LOG_IF(FATAL, !status.ok())
      << "Failed to configure EnclaveManager: " << status;

  // Create a loader for the application enclave.
  asylo::SgxEmbeddedLoader loader(asylo::kSectionName, /*debug=*/true);

  // Run the application driver workflow.
  auto main_return = asylo::ApplicationWrapperDriverMain(
      loader, asylo::kEnclaveName, argc, argv);
  LOG_IF(FATAL, !main_return.ok())
      << "Failed to run the whole-application wrapper: "
      << main_return.status();

  // Return the return value from main().
  return main_return.value();
}
