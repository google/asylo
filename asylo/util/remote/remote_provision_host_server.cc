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

#include "absl/base/attributes.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/util/remote/grpc_server_main_wrapper.h"
#include "asylo/util/remote/process_main_wrapper.h"
#include "asylo/util/remote/remote_provision_server_lib.h"

ABSL_FLAG(
    int32_t, port, 0,
    "Port for provision server to use. If set to 0, server will choose and "
    "assign port and then communicate it to the caller over stdout.");

ABSL_FLAG(std::string, temporary_directory, "/tmp",
          "Temporary directory to store enclaves");

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  const auto status = ::asylo::ProcessMainWrapper<
      ::asylo::GrpcServerMainWrapper<::asylo::RemoteProvisionServer>>::
      RunUntilTerminated(absl::GetFlag(FLAGS_port),
                         absl::GetFlag(FLAGS_temporary_directory));
  if (!status.ok()) {
    LOG(ERROR) << "Failed to run, status=" << status;
    return -1;
  }
  return 0;
}
