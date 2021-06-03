/*
 *
 * Copyright 2019 Asylo authors
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

#include <cstdint>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "asylo/enclave_manager.h"
#include "asylo/examples/secure_grpc/grpc_client_util.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"

constexpr char kServerAddress[] = "localhost";

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(int32_t, port, 0, "Port that the server listens to");
ABSL_FLAG(std::string, word_to_translate, "", "Word to be translated");
ABSL_FLAG(bool, debug, true, "Whether to use a debug enclave");

int main(int argc, char *argv[]) {
  // Parse command-line arguments.
  absl::ParseCommandLine(argc, argv);

  std::string word_to_translate = absl::GetFlag(FLAGS_word_to_translate);
  LOG_IF(QFATAL, word_to_translate.empty())
      << "--word_to_translate cannot be empty";

  std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, enclave_path.empty()) << "--enclave_path cannot be empty";

  int32_t port = absl::GetFlag(FLAGS_port);
  LOG_IF(QFATAL, port == 0) << "--port cannot be 0";

  asylo::Status status =
      asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  LOG_IF(QFATAL, !status.ok())
      << "Failed to configure EnclaveManager: " << status;

  status = examples::secure_grpc::LoadGrpcClientEnclave(
      enclave_path, absl::GetFlag(FLAGS_debug));
  LOG_IF(QFATAL, !status.ok())
      << "Loading " << enclave_path << " failed: " << status;

  asylo::StatusOr<std::string> run_result =
      examples::secure_grpc::GrpcClientEnclaveGetTranslation(
          absl::StrCat(kServerAddress, ":", port), word_to_translate);
  LOG_IF(QFATAL, !run_result.ok())
      << "Getting translation for " << word_to_translate
      << " failed: " << run_result.status();

  std::cout << "Translation for \"" << word_to_translate << "\" is \""
            << run_result.value() << "\"" << std::endl;

  status = examples::secure_grpc::DestroyGrpcClientEnclave();
  LOG_IF(QFATAL, !status.ok())
      << "Destroy " << enclave_path << " failed: " << status;

  return 0;
}
