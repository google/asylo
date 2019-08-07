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

#include "asylo/platform/host_call/untrusted/host_call_handlers.h"

#include <errno.h>
#include <unistd.h>

#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/platform/system_call/untrusted_invoke.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace host_call {

Status SystemCallHandler(const std::shared_ptr<primitives::Client> &client,
                         void *context, primitives::MessageReader *input,
                         primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  auto request = input->next();

  primitives::Extent response;  // To be owned by untrusted call parameters.
  primitives::PrimitiveStatus status =
      system_call::UntrustedInvoke(request, &response);
  if (!status.ok()) {
    return primitives::MakeStatus(status);
  }
  output->PushByCopy(response);
  free(response.data());

  return Status::OkStatus();
}

Status IsAttyHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int fd = input->next<int>();
  output->Push<int>(isatty(fd));  // Push return value first.
  output->Push<int>(
      errno);  // Push errno next. We always push the errno on the MessageWriter
               // regardless of the return value of the host call. The caller is
               // responsible for evaluating the return value and setting the
               // errno appropriately in its local environment.
  return Status::OkStatus();
}

Status USleepHandler(const std::shared_ptr<primitives::Client> &client,
                     void *context, primitives::MessageReader *input,
                     primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  auto usec = input->next<useconds_t>();
  output->Push<int>(usleep(usec));  // Push return value first.
  output->Push<int>(errno);         // Push errno next.
  return Status::OkStatus();
}

Status SysconfHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 1);
  int kLinux_name = input->next<int>();
  output->Push<int64_t>(sysconf(kLinux_name));  // Push return value first.
  output->Push<int>(errno);                     // Push errno next.
  return Status::OkStatus();
}

Status ReadWithUntrustedPtrHandler(
    const std::shared_ptr<primitives::Client> &client, void *context,
    primitives::MessageReader *input, primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 3);
  int fd = input->next<int>();
  void *untrusted_buf = input->next<void *>();
  auto size = input->next<size_t>();

  output->Push<int64_t>(
      read(fd, untrusted_buf, size));  // Push return value first.
  output->Push<int>(errno);            // Push errno next.
  return Status::OkStatus();
}

Status ReallocHandler(const std::shared_ptr<primitives::Client> &client,
                      void *context, primitives::MessageReader *input,
                      primitives::MessageWriter *output) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*input, 2);
  void *in_ptr = input->next<void *>();
  size_t size = input->next<size_t>();
  void *out_ptr = realloc(in_ptr, size);
  output->Push(reinterpret_cast<uint64_t>(out_ptr));
  output->Push<int>(errno);
  return Status::OkStatus();
}

}  // namespace host_call
}  // namespace asylo
