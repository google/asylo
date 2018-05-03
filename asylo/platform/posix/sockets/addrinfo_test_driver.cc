/*
 *
 * Copyright 2017 Asylo authors
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

#include <gtest/gtest.h>
#include "asylo/platform/posix/sockets/socket_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

class AddrinfoTest : public EnclaveTest {
 protected:
  void SetEnclaveInput(EnclaveInput *enclave_input, bool use_addrinfo_hints) {
    AddrInfoTestInput test_input;
    test_input.set_use_addrinfo_hints(use_addrinfo_hints);
    *enclave_input->MutableExtension(addrinfo_test_input) = test_input;
  }
};

// Tests getaddrinfo() and freeaddrinfo() without any hints
TEST_F(AddrinfoTest, AddrinfoNoHintsTest) {
  EnclaveInput enclave_input;
  SetEnclaveInput(&enclave_input, /*use_addrinfo_hints=*/false);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
}

// Tests getaddrinfo() and freeaddrinfo() with addrinfo hints
TEST_F(AddrinfoTest, AddrinfoHintsTest) {
  EnclaveInput enclave_input;
  SetEnclaveInput(&enclave_input, /*use_addrinfo_hints=*/true);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
}

}  // namespace
}  // namespace asylo
