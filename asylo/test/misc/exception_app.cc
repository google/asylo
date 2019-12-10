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

#include <cstdlib>
#include <string>

#include "asylo/client.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/enclave_test_launcher.h"

namespace asylo {
namespace {

class ExceptionTest {
 public:
  ExceptionTest() : client_(nullptr) {}

  void Initialize(const std::string &enclave_path) {
    ::asylo::Status status = test_launcher_.SetUp(enclave_path, {}, "");
    if (!status.ok()) {
      LOG(ERROR) << "Setup failed: " << status;
      exit(EXIT_FAILURE);
    }
    client_ = test_launcher_.mutable_client();
  }

  ~ExceptionTest() {
    if (client_) {
      test_launcher_.TearDown({});
    }
  }

  void Run(const std::string &enclave_path, const std::string &input) {
    Initialize(enclave_path);

    EnclaveInput enclave_input;
    EnclaveTestLauncher::SetEnclaveInputTestString(&enclave_input, input);
    if ((input == "caught") !=
        client_->EnterAndRun(enclave_input, nullptr).ok()) {
      exit(2);
    }
  }

 protected:
  EnclaveTestLauncher test_launcher_;
  EnclaveClient *client_;
};

}  // namespace
}  // namespace asylo

int main(int argc, char *argv[]) {
  if (argc != 3) {
    LOG(ERROR) << "Expected usage: " << argv[0] << " <enclave-path>\nGiven: ";
    for (int i = 0; i < argc; ++i) {
      LOG(ERROR) << argv[i];
    }
    abort();
  }

  asylo::ExceptionTest test;

  test.Run(argv[1], argv[2]);
  return 0;
}
