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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_PROC_SYSTEM_SERVICE_CLIENT_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_PROC_SYSTEM_SERVICE_CLIENT_H_

#include "asylo/platform/primitives/remote/metrics/proc_system.grpc.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.pb.h"
#include "asylo/util/statusor.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/support/status.h"
#include "include/grpcpp/channel.h"

namespace asylo {
namespace primitives {

class ProcSystemServiceClient {
 public:
  // Constructor for when a specific StubInterface is required.
  explicit ProcSystemServiceClient(
      std::shared_ptr<ProcSystemService::StubInterface> stub);

  // General purpose constructor, utilizes default StubInterface
  explicit ProcSystemServiceClient(
      const std::shared_ptr<::grpc::Channel> &channel);

  ::asylo::StatusOr<ProcStatResponse> GetProcStat() const;

 private:
  const std::shared_ptr<ProcSystemService::StubInterface> stub_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_PROC_SYSTEM_SERVICE_CLIENT_H_
