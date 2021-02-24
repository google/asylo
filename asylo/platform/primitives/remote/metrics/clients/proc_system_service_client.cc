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

#include "asylo/platform/primitives/remote/metrics/clients/proc_system_service_client.h"

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.grpc.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace primitives {

ProcSystemServiceClient::ProcSystemServiceClient(
    std::shared_ptr<ProcSystemService::StubInterface> stub)
    : stub_(CHECK_NOTNULL(stub)) {}

::asylo::StatusOr<ProcStatResponse> ProcSystemServiceClient::GetProcStat()
    const {
  ProcStatRequest request;
  ProcStatResponse response;
  ::grpc::ClientContext context;

  auto status = stub_->GetProcStat(&context, request, &response);
  if (!status.ok()) {
    return ConvertStatus<absl::Status>(status);
  }
  return response;
}

ProcSystemServiceClient::ProcSystemServiceClient(
    const std::shared_ptr<::grpc::Channel> &channel)
    : stub_(std::make_shared<ProcSystemService::Stub>(channel)) {}

}  // namespace primitives
}  // namespace asylo
