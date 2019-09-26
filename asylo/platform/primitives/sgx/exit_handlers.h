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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_EXIT_HANDLERS_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_EXIT_HANDLERS_H_

#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

// Exit call handler for thread creation. Performs an EnclaveCall to register
// and start the thread this handler creates.
ASYLO_MUST_USE_RESULT Status CreateThreadHandler(
    const std::shared_ptr<primitives::Client> &client, void *context,
    primitives::MessageReader *input, primitives::MessageWriter *output);

// Registers the exit handlers specific to SGX primitives layer.
ASYLO_MUST_USE_RESULT Status
RegisterSgxExitHandlers(Client::ExitCallProvider *exit_call_provider);

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_EXIT_HANDLERS_H_
