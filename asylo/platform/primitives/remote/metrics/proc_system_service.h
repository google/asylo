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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_PROC_SYSTEM_SERVICE_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_PROC_SYSTEM_SERVICE_H_

#include "asylo/platform/primitives/remote/metrics/proc_system.grpc.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_parser.h"
#include "asylo/util/status.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace primitives {

class ProcSystemServiceImpl : public ProcSystemService::Service {
 public:
  explicit ProcSystemServiceImpl(pid_t pid)
      : proc_system_parser_(CreateProcSystemParser()), pid_(pid) {}
  ProcSystemServiceImpl(const ProcSystemServiceImpl &other) = delete;
  ProcSystemServiceImpl &operator=(const ProcSystemServiceImpl &other) = delete;

  ::grpc::Status GetProcStat(::grpc::ServerContext *context,
                             const ProcStatRequest *request,
                             ProcStatResponse *response) override;

 protected:
  ProcSystemServiceImpl(std::unique_ptr<ProcSystemParser> proc_system_parser,
                        pid_t pid)
      : proc_system_parser_(std::move(proc_system_parser)), pid_(pid) {}

 private:
  std::unique_ptr<ProcSystemParser> CreateProcSystemParser() const;

  ::asylo::Status BuildProcStatResponse(ProcStatResponse *response) const;

  std::unique_ptr<ProcSystemParser> proc_system_parser_;
  const pid_t pid_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_PROC_SYSTEM_SERVICE_H_
