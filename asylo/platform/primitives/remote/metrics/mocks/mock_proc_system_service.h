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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_SERVICE_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_SERVICE_H_

#include <memory>

#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_parser.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_service.h"

namespace asylo {
namespace primitives {

class MockProcSystemService : public ProcSystemServiceImpl {
 public:
  MockProcSystemService(std::unique_ptr<ProcSystemParser> parser, pid_t pid)
      : ProcSystemServiceImpl(std::move(parser), pid) {}
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_SERVICE_H_
