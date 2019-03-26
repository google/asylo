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

#include "asylo/platform/system_call/message.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "asylo/platform/system_call/metadata.h"

namespace asylo {
namespace system_call {

namespace {

uint64_t RoundUpToMultipleOf8(uint64_t value) {
  return value + (8 - value % 8) % 8;
}

}  // namespace

std::string FormatMessage(primitives::Extent extent) {
  MessageReader reader(extent);
  std::string result;

  absl::StrAppend(&result, reader.is_request() ? "request: " : "response: ");

  SystemCallDescriptor descriptor(reader.sysno());
  absl::StrAppend(&result, descriptor.name());
  if (reader.is_response()) {
    absl::StrAppend(&result, " [returns: ", reader.result(), "] ");
  }

  std::vector<std::string> formatted;
  for (int i = 0; i < descriptor.parameter_count(); i++) {
    if (!reader.parameter_is_used(i)) continue;
    ParameterDescriptor parameter = descriptor.parameter(i);
    std::string str = absl::StrCat(i, ": ", parameter.name());
    if (parameter.is_scalar()) {
      absl::StrAppend(&str, " [scalar ", reader.parameter<uint64_t>(i), "]");
    } else if (reader.parameter_size(i) == 0) {
      absl::StrAppend(&str, " [nullptr]");
    } else if (parameter.is_string()) {
      absl::StrAppend(&str, " [string \"",
                      reader.parameter_address<const char *>(i), "\"]");
    } else if (parameter.is_fixed()) {
      absl::StrAppend(&str, " [fixed ", reader.parameter_size(i), "]");
    } else if (parameter.is_bounded()) {
      absl::StrAppend(&str, " [bounded ", reader.parameter_size(i), "]");
    } else {
      str = " <unexpected value>";
    }
    formatted.push_back(str);
  }

  absl::StrAppend(&result, "(", absl::StrJoin(formatted, ", "), ")");
  return result;
}

primitives::PrimitiveStatus MessageReader::Validate() const {
  return true;
}

bool MessageReader::parameter_is_used(int index) const {
  SystemCallDescriptor syscall(sysno());
  ParameterDescriptor parameter = syscall.parameter(index);

  if (!parameter.is_valid()) {
    return false;
  }

  // Output-only parameters are not included in the encoding of requests.
  if (is_request() && !parameter.is_in()) {
    return false;
  }

  // Input-only parameters are not included in the encoding of responses.
  if (is_response() && !parameter.is_out()) {
    return false;
  }

  return true;
}

MessageWriter::MessageWriter(
    int sysno, uint64_t result, bool is_request,
    const std::array<uint64_t, kParameterMax> &parameters)
    : sysno_(sysno),
      result_(result),
      is_request_(is_request),
      parameters_(parameters) {
  SystemCallDescriptor syscall{sysno};
  for (int i = 0; i < kParameterMax; i++) {
    parameter_size_[i] = ParameterSize(syscall.parameter(i));
  }
}

MessageWriter MessageWriter::RequestWriter(
    int sysno, const std::array<uint64_t, kParameterMax> &parameters) {
  return MessageWriter(sysno, 0, true, parameters);
}

MessageWriter MessageWriter::ResponseWriter(
    int sysno, uint64_t result,
    const std::array<uint64_t, kParameterMax> &parameters) {
  return MessageWriter(sysno, result, false, parameters);
}

size_t MessageWriter::MessageSize() const {
  size_t result = sizeof(MessageHeader);
  for (int i = 0; i < kParameterMax; i++) {
    result += RoundUpToMultipleOf8(parameter_size_[i]);
  }
  return result;
}

bool MessageWriter::parameter_is_used(int index) const {
  SystemCallDescriptor syscall(sysno_);
  ParameterDescriptor parameter = syscall.parameter(index);

  if (!parameter.is_valid()) {
    return false;
  }

  // Output-only parameters are not included in the encoding of requests.
  if (is_request() && !parameter.is_in()) {
    return false;
  }

  // Input-only parameters are not included in the encoding of responses.
  if (is_response() && !parameter.is_out()) {
    return false;
  }

  return true;
}

size_t MessageWriter::ParameterSize(ParameterDescriptor parameter) const {
  SystemCallDescriptor syscall(sysno_);

  // Return a size of zero for unused parameters.
  if (!parameter_is_used(parameter.index())) {
    return 0;
  }

  // All scalar values are encoded using 64 bits.
  if (parameter.is_scalar()) {
    return sizeof(uint64_t);
  }

  uint64_t value = parameters_[parameter.index()];

  // Null pointer parameters are encoded as zero size fields.
  if (value == 0) {
    return 0;
  }

  if (parameter.is_fixed()) {
    return parameter.size();
  }

  if (parameter.is_string()) {
    return strlen(reinterpret_cast<const char *>(value)) + 1;
  }

  if (parameter.is_bounded()) {
    return parameters_[parameter.bounding_parameter().index()];
  }

  // The following line is expected to be unreachable.
  abort();
}

bool MessageWriter::Write(primitives::Extent *message) const {
  auto *header = reinterpret_cast<MessageHeader *>(message->data());
  header->magic = kMessageMagic;
  header->flags = is_request_ ? kSystemCallRequest : kSystemCallResponse;
  header->sysno = sysno_;

  // If this is a response message, add the result value to the message header.
  if (is_response()) {
    header->result = result_;
  }

  // Write each parameter value into the buffer.
  std::size_t next_offset = sizeof(MessageHeader);

  SystemCallDescriptor syscall(sysno_);
  for (int i = 0; i < kParameterMax; i++) {
    ParameterDescriptor parameter = syscall.parameter(i);
    if (!parameter_is_used(i)) {
      continue;
    }

    // If this parameter is a pointer and not null, then copy its contents into
    // the body of the message. Null pointers are encoded as having a size of
    // zero.
    if (parameter.is_pointer()) {
      if (void *src = reinterpret_cast<void *>(parameters_[i])) {
        memcpy(message->As<uint8_t>() + next_offset, src, parameter_size_[i]);
      }
    } else {
      // Otherwise, this is a scalar value which is zero-extended to 64-bits and
      // written into the message body.
      *reinterpret_cast<uint64_t *>(message->As<uint8_t>() + next_offset) =
          parameters_[i];
    }
    header->offset[i] = next_offset;
    header->size[i] = parameter_size_[i];
    next_offset = RoundUpToMultipleOf8(next_offset + parameter_size_[i]);
  }

  return true;
}

}  // namespace system_call
}  // namespace asylo
