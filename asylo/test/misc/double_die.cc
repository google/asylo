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

#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"

namespace asylo {
namespace {

jmp_buf env;

void on_SIGILL(int /* signum */) { longjmp(env, 1); }

class DieTest {
 public:
  void Initialize(const std::string &enclave_path) {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    if (!manager_result.ok()) {
      std::cerr << manager_result.status() << std::endl;
      exit(1);
    }
    manager_ = manager_result.value();
    std::cerr << "Init " << enclave_path << std::endl;
    std::string enclave_url = "/die";

    // Create an EnclaveLoadConfig object.
    EnclaveLoadConfig load_config;
    load_config.set_name(enclave_url);

    // Create an SgxLoadConfig object.
    SgxLoadConfig sgx_config;
    SgxLoadConfig::FileEnclaveConfig file_enclave_config;
    file_enclave_config.set_enclave_path(enclave_path);
    *sgx_config.mutable_file_enclave_config() = file_enclave_config;
    sgx_config.set_debug(true);

    // Set an SGX message extension to load_config.
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    Status status = manager_->LoadEnclave(load_config);
    ASSERT_TRUE(status.ok());
    client_ = manager_->GetClient(enclave_url);
  }

  ~DieTest() {
    // We can't call finalize because the enclave is crashed.
    EnclaveFinal efinal;
    manager_->DestroyEnclave(client_, efinal);
  }

  void Run(const std::string &enclave_path) {
    Initialize(enclave_path);

    struct sigaction sa;
    memset(&sa, '\0', sizeof(struct sigaction));
    sa.sa_handler = &on_SIGILL;
    sigaction(SIGILL, &sa, nullptr);

    if (setjmp(env) == 0) {
      EnclaveInput einput;
      std::cerr << "Round one" << std::endl;
      client_->EnterAndRun(einput, nullptr);
      std::cerr << "Unreachable?" << std::endl;
      std::cerr << "Abort handler should activate first." << std::endl;
      exit(1);
    } else {
      EnclaveInput einput;
      std::cerr << "Going again" << std::endl;
      // Reentry calls exit(EXIT_FAILURE) due to tcs_state != TCS_STATE_INACTIVE
      client_->EnterAndRun(einput, nullptr);
      std::cerr << "Can't reenter in inconsistent state." << std::endl;
      exit(1);
    }
  }

  void SimpleRun(const std::string &enclave_path) {
    Initialize(enclave_path);
    EnclaveInput einput;
    client_->EnterAndRun(einput, nullptr);
  }

 protected:
  EnclaveManager *manager_;
  EnclaveClient *client_;
};

}  // namespace
}  // namespace asylo

int main(int argc, char *argv[]) {
  if (argc != 2 && argc != 3) {
    std::cerr << "Expected usage: " << argv[0]
              << " <enclave-path> [--die]"
                 "\nGiven: ";
    for (int i = 0; i < argc; ++i) {
      std::cerr << argv[i] << std::endl;
    }
    abort();
  }

  asylo::DieTest test;

  if (argc == 2 && strcmp(argv[1], "--sigill") == 0) {
    __builtin_trap();
  }
  if (argc == 3 && strcmp(argv[2], "--die") == 0) {
    test.SimpleRun(argv[1]);
  } else {
    test.Run(argv[1]);
  }
  return 0;
}
