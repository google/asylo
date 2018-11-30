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

#ifndef ASYLO_TEST_UTIL_MOCK_ENCLAVE_LOADER_H_
#define ASYLO_TEST_UTIL_MOCK_ENCLAVE_LOADER_H_

#include <gmock/gmock.h>
#include "asylo/client.h"
#include "asylo/util/status.h"

namespace asylo {

// A mock class to use for testing the interaction between loaders and clients.
class MockEnclaveLoader : public EnclaveLoader {
 public:
  MOCK_CONST_METHOD3(LoadEnclave, StatusOr<std::unique_ptr<EnclaveClient>>(
                                      const std::string& name, void* base_address,
                                      const EnclaveConfig& config));

  MOCK_CONST_METHOD0(Copy, StatusOr<std::unique_ptr<EnclaveLoader>>());
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_MOCK_ENCLAVE_LOADER_H_
