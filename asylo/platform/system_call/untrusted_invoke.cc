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

#include "asylo/platform/system_call/untrusted_invoke.h"

#include <errno.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "asylo/platform/system_call/metadata.h"
#include "asylo/platform/system_call/serialize.h"

namespace asylo {
namespace system_call {

primitives::PrimitiveStatus UntrustedInvoke(primitives::Extent request,
                                            primitives::Extent *response) {
  MessageReader reader(request);
  SystemCallDescriptor descriptor(reader.sysno());

  // Parameters passed to a native system call.
  std::array<uint64_t, kParameterMax> params;
  params.fill(0);

  // A vector of buffers allocated for output params.
  std::vector<std::unique_ptr<char[]>> output_buffers;

  for (int i = 0; i < kParameterMax; i++) {
    ParameterDescriptor parameter = descriptor.parameter(i);
    if (parameter.is_in()) {
      // Read an input parameter from the request.
      if (parameter.is_pointer()) {
        params[i] = reader.parameter_address<uint64_t>(i);
      } else {
        params[i] = reader.parameter<uint64_t>(i);
      }
    } else if (parameter.is_out()) {
      // Otherwise, allocate storage for the result.
      size_t size;
      if (parameter.is_bounded()) {
        int bounding_index = parameter.bounding_parameter().index();
        size =
            reader.parameter<size_t>(bounding_index) * parameter.element_size();
      } else {
        size = parameter.size();
      }
      output_buffers.emplace_back(new char[size]());
      params[i] = reinterpret_cast<uint64_t>(output_buffers.back().get());
    }
  }

  // Invoke the native system call.
  uint64_t result = syscall(reader.sysno(), params[0], params[1], params[2],
                            params[3], params[4], params[5]);

  // Build the response message.
  return SerializeResponse(reader.sysno(), result, errno, params, response);
}

}  // namespace system_call
}  // namespace asylo
