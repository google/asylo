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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_STATUS_SERIALIZER_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_STATUS_SERIALIZER_H_

#include <sys/types.h>

#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/util/status.h"

namespace asylo {

// StatusSerializer can be used to serialize a given proto2 message to an
// untrusted buffer.
//
// OutputProto must be a proto2 message type.
template <class OutputProto>
class StatusSerializer {
 public:
  // Creates a new StatusSerializer that saves Status objects to |status_proto|,
  // which is a nested message within |output_proto|. StatusSerializer does not
  // take ownership of any of the input pointers. Input pointers must remain
  // valid for the lifetime of the StatusSerializer.
  StatusSerializer(const OutputProto *output_proto, StatusProto *status_proto,
                   char **output, size_t *output_len,
                   std::function<void *(size_t)> allocator = &malloc)
      : output_proto_{output_proto},
        status_proto_{status_proto},
        output_{output},
        output_len_{output_len},
        allocator_{std::move(allocator)} {}

  // Creates a new StatusSerializer that saves Status objects to |status_proto|.
  // StatusSerializer does not take ownership of any of the input pointers.
  // Input pointers must remain valid for the lifetime of the StatusSerializer.
  StatusSerializer(char **output, size_t *output_len,
                   std::function<void *(size_t)> allocator = &malloc)
      : output_proto_{&proto_},
        status_proto_{&proto_},
        output_{output},
        output_len_{output_len},
        allocator_{std::move(allocator)} {}

  // Saves the given |status| into the StatusSerializer's status_proto_. Then
  // serializes its output_proto_ into a buffer. On success 0 is returned, else
  // 1 is returned and the StatusSerializer logs the error. Since this method
  // can potentially perform a copy to untrusted memory depending on the value
  // of allocator_, it should not be used for backends that cannot access
  // untrusted memory directly.
  int Serialize(const Status &status) {
    status.SaveTo(status_proto_);

    // Serialize to a trusted buffer instead of an untrusted buffer because the
    // serialization routine may rely on read backs for correctness.
    *output_len_ = output_proto_->ByteSizeLong();
    std::unique_ptr<char[]> trusted_output(new char[*output_len_]);
    if (!output_proto_->SerializeToArray(trusted_output.get(), *output_len_)) {
      *output_ = nullptr;
      *output_len_ = 0;
      primitives::TrustedPrimitives::DebugPuts(status.ToString().c_str());
      return 1;
    }

    *output_ = reinterpret_cast<char *>(allocator_(*output_len_));
    memcpy(*output_, trusted_output.get(), *output_len_);
    return 0;
  }

 private:
  OutputProto proto_;
  const OutputProto *output_proto_;
  StatusProto *status_proto_;
  char **output_;
  size_t *output_len_;
  std::function<void *(size_t)> allocator_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_STATUS_SERIALIZER_H_
