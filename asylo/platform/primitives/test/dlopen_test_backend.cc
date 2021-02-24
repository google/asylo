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

#include "asylo/platform/primitives/test/dlopen_test_backend.h"

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/platform/primitives/dlopen/untrusted_dlopen.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, enclave_binary, "",
          "Path to the Sim enclave binary to be loaded");

namespace asylo {
namespace primitives {
namespace test {

StatusOr<std::shared_ptr<Client>> DlopenTestBackend::LoadTestEnclave(
    const absl::string_view enclave_name,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  const std::string binary_path = absl::GetFlag(FLAGS_enclave_binary);
  if (binary_path.empty()) {
    return absl::InvalidArgumentError("--enclave_binary must be set");
  }
  return LoadEnclave<DlopenBackend>(enclave_name, binary_path,
                                    std::move(exit_call_provider));
}

TestBackend *TestBackend::Get() {
  static TestBackend *backend = new DlopenTestBackend;
  return backend;
}

}  // namespace test
}  // namespace primitives
}  // namespace asylo
