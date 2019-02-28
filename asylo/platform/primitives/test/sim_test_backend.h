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

#ifndef ASYLO_PLATFORM_PRIMITIVES_TEST_SIM_TEST_BACKEND_H_
#define ASYLO_PLATFORM_PRIMITIVES_TEST_SIM_TEST_BACKEND_H_

#include "asylo/platform/primitives/sim/untrusted_sim.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {
namespace test {

class SimTestBackend : public TestBackend {
 public:
  SimTestBackend() = default;

  // Loads an instance of a sim test enclave, aborting on failure.
  StatusOr<std::shared_ptr<EnclaveClient>> LoadTestEnclave(
      std::unique_ptr<EnclaveClient::ExitCallProvider> exit_call_provider)
      override;

  // Signals to ignore memory leak checking on abort tests.
  bool LeaksMemoryOnAbort() override { return true; }
};

}  // namespace test
}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_TEST_SIM_TEST_BACKEND_H_
