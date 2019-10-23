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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_SERVICE_SERVER_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_SERVICE_SERVER_H_

#include <memory>

#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_service.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {
namespace primitives {

// MockProcSystemServiceServer is meant to be utilized with
// primitives::GrpcServerMainWrapper and is for testing ProcSystemServiceClient
// and its dependencies.
class MockProcSystemServiceServer {
 public:
  static ::asylo::StatusOr<std::unique_ptr<MockProcSystemServiceServer>> Create(
      ::grpc::ServerBuilder *builder, std::unique_ptr<ProcSystemParser> parser,
      int64_t pid);

 private:
  MockProcSystemServiceServer() = default;

  std::unique_ptr<MockProcSystemService> mock_proc_system_service_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_SERVICE_SERVER_H_
