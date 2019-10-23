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

#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_service_server.h"

#include <memory>

#include "absl/memory/memory.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {
namespace primitives {

::asylo::StatusOr<std::unique_ptr<MockProcSystemServiceServer>>
MockProcSystemServiceServer::Create(::grpc::ServerBuilder *builder,
                                    std::unique_ptr<ProcSystemParser> parser,
                                    int64_t pid) {
  auto server = absl::WrapUnique(new MockProcSystemServiceServer());
  server->mock_proc_system_service_ =
      absl::make_unique<MockProcSystemService>(std::move(parser), pid);

  builder->RegisterService(server->mock_proc_system_service_.get());

  return server;
}

}  // namespace primitives
}  // namespace asylo
