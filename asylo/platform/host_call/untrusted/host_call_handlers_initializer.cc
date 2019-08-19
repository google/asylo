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

#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"

#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace host_call {

StatusOr<std::unique_ptr<primitives::Client::ExitCallProvider>>
GetHostCallHandlersMapping() {
  std::unique_ptr<primitives::Client::ExitCallProvider> dispatch_table =
      absl::make_unique<primitives::DispatchTable>();

  ASYLO_RETURN_IF_ERROR(
      AddHostCallHandlersToExitCallProvider(dispatch_table.get()));

  return std::move(dispatch_table);
}

Status AddHostCallHandlersToExitCallProvider(
    primitives::Client::ExitCallProvider *exit_call_provider) {
  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kSystemCallHandler, primitives::ExitHandler{SystemCallHandler}));

  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kIsAttyHandler, primitives::ExitHandler{IsAttyHandler}));

  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kUSleepHandler, primitives::ExitHandler{USleepHandler}));

  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kSysconfHandler, primitives::ExitHandler{SysconfHandler}));

  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kReallocHandler, primitives::ExitHandler{ReallocHandler}));

  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kSleepHandler, primitives::ExitHandler{SleepHandler}));

  ASYLO_RETURN_IF_ERROR(exit_call_provider->RegisterExitHandler(
      kSendMsgHandler, primitives::ExitHandler{SendMsgHandler}));

  return Status::OkStatus();
}

}  // namespace host_call
}  // namespace asylo
