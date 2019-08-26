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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TEST_REMOTE_TEST_BACKEND_H_
#define ASYLO_PLATFORM_PRIMITIVES_TEST_REMOTE_TEST_BACKEND_H_

#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {
namespace test {

class RemoteTestBackend : public TestBackend {
 public:
  RemoteTestBackend() = default;
  ~RemoteTestBackend() override;

  void FinalizeTestEnclave();

  // Loads a proxy client to access an instance of a sim test enclave
  // remotely, aborting on failure.
  StatusOr<std::shared_ptr<Client>> LoadTestEnclave(
      const absl::string_view enclave_name,
      std::unique_ptr<Client::ExitCallProvider> exit_call_provider) override;

 private:
  pid_t remote_target_pid_ = 0;
};

}  // namespace test
}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_TEST_REMOTE_TEST_BACKEND_H_
