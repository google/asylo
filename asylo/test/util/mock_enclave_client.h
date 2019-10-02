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

#ifndef ASYLO_TEST_UTIL_MOCK_ENCLAVE_CLIENT_H_
#define ASYLO_TEST_UTIL_MOCK_ENCLAVE_CLIENT_H_

#include <gmock/gmock.h>
#include "absl/strings/string_view.h"
#include "asylo/client.h"
#include "asylo/util/status.h"

namespace asylo {

// A mock class to use for testing the interaction between wrappers and their
// enclaves.
class MockEnclaveClient : public EnclaveClient {
 public:
  MockEnclaveClient() : EnclaveClient("mock") {}

  MOCK_METHOD2(EnterAndRun, Status(const EnclaveInput &, EnclaveOutput *));
  MOCK_CONST_METHOD0(get_name, absl::string_view());
  MOCK_METHOD1(EnterAndInitialize, Status(const EnclaveConfig &));
  MOCK_METHOD1(EnterAndFinalize, Status(const EnclaveFinal &));
  MOCK_METHOD0(DestroyEnclave, Status());
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_MOCK_ENCLAVE_CLIENT_H_
