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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/system_call/metadata.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace system_call {

namespace {

// Returns the smallest multiple of 8 greater than or equal to |value|, or 0 on
// integer overflow.
uint64_t RoundUpToMultipleOf8(uint64_t value) {
  return value + (8 - value % 8) % 8;
}

// Returns the largest multiple of 8 less than or equal to |value|.
uint64_t RoundDownToMultipleOf8(uint64_t value) { return (value / 8) * 8; }

// Returns true if the sum of two input values overflow, after round up to
// multiple of 8.
bool SumOverflowOnRoundUpToMultipleOf8(uint64_t v1, uint64_t v2) {
  return v2 > RoundDownToMultipleOf8(SIZE_MAX) ||
         v1 > RoundDownToMultipleOf8(SIZE_MAX) - v2;
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
    absl::StrAppend(&result, " [errno: ", reader.error_number(), "] ");
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

bool MessageReader::IsValidParameterSize(int index) const {
  if (!parameter_is_used(index)) {
    return true;
  }

  SystemCallDescriptor syscall(sysno());
  ParameterDescriptor parameter = syscall.parameter(index);
  if (parameter.is_scalar()) {
    return header()->size[index] == sizeof(uint64_t);
  }

  if (parameter.is_fixed()) {
    return header()->size[index] == parameter.size();
  }

  if (header()->size[index] == 0) {
    return true;
  }

  if (parameter.is_string()) {
    const char *value =
        this->parameter_address<const char *>(parameter.index());

    if (value[header()->size[index] - 1] != '\0') {
      return false;
    }

    return header()->size[index] == strlen(value) + 1;
  }

  // Bounded parameter size could not be verified here, simply return true.
  // The general validations that checks parameter size does not extend outside
  // the message still apply.
  if (parameter.is_bounded()) {
    return true;
  }

  // The following line is expected to be unreachable.
  abort();
}

primitives::PrimitiveStatus MessageReader::invalid_argument_status(
    const std::string &reason) const {
  return primitives::PrimitiveStatus{
      primitives::AbslStatusCode::kInvalidArgument, reason};
}

primitives::PrimitiveStatus MessageReader::ValidateMessageHeader() const {
  size_t next_offset = sizeof(MessageHeader);
  if (extent_.size() < next_offset) {
    return invalid_argument_status(
        "Message malformed: no completed header present");
  }

  if (header()->magic != kMessageMagic) {
    return invalid_argument_status(
        "Message malformed: magic number mismatched");
  }

  if (is_request() == is_response()) {
    return invalid_argument_status(
        "Message malformed: should be either a request or a response");
  }

  SystemCallDescriptor syscall(sysno());

  if (!syscall.is_valid()) {
    return invalid_argument_status(
        absl::StrCat("Message malformed: sysno ", sysno(), " is invalid"));
  }

  return primitives::PrimitiveStatus::OkStatus();
}

primitives::PrimitiveStatus MessageReader::Validate() const {
  ASYLO_RETURN_IF_ERROR(ValidateMessageHeader());

  size_t next_offset = sizeof(MessageHeader);
  SystemCallDescriptor syscall(sysno());

  for (int i = 0; i < kParameterMax; i++) {
    ParameterDescriptor parameter = syscall.parameter(i);
    if (!parameter_is_used(parameter)) {
      continue;
    }

    if (header()->offset[i] != next_offset) {
      return invalid_argument_status(
          absl::StrCat("Message malformed: parameter under index ", i,
                       " has drifted offset"));
    }

    if (SumOverflowOnRoundUpToMultipleOf8(header()->size[i], next_offset)) {
      return invalid_argument_status(
          absl::StrCat("Message malformed: parameter under index ", i,
                       " resides above max offset"));
    }

    next_offset = RoundUpToMultipleOf8(next_offset + header()->size[i]);
    if (next_offset > extent_.size()) {
      return invalid_argument_status(
          absl::StrCat("Message malformed: parameter under index ", i,
                       " overflowed from buffer memory"));
    }

    if (!IsValidParameterSize(i)) {
      return invalid_argument_status(absl::StrCat(
          "Message malformed: parameter under index ", i, " size mismatched"));
    }
  }

  return primitives::PrimitiveStatus::OkStatus();
}

bool MessageReader::parameter_is_used(ParameterDescriptor parameter) const {
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

bool MessageReader::parameter_is_used(int index) const {
  SystemCallDescriptor syscall(sysno());
  ParameterDescriptor parameter = syscall.parameter(index);
  return parameter_is_used(parameter);
}

MessageWriter::MessageWriter(
    int sysno, uint64_t result, uint64_t error_number, bool is_request,
    const std::array<uint64_t, kParameterMax> &parameters)
    : sysno_(sysno),
      result_(result),
      error_number_(error_number),
      is_request_(is_request),
      parameters_(parameters) {
  SystemCallDescriptor syscall{sysno};
  for (int i = 0; i < kParameterMax; i++) {
    parameter_size_[i] = ParameterSize(syscall.parameter(i));
  }
}

MessageWriter MessageWriter::RequestWriter(
    int sysno, const std::array<uint64_t, kParameterMax> &parameters) {
  return MessageWriter(sysno, 0, 0, true, parameters);
}

MessageWriter MessageWriter::ResponseWriter(
    int sysno, uint64_t result, uint64_t error_number,
    const std::array<uint64_t, kParameterMax> &parameters) {
  return MessageWriter(sysno, result, error_number, false, parameters);
}

size_t MessageWriter::MessageSize() const {
  size_t result = sizeof(MessageHeader);
  for (int i = 0; i < kParameterMax; i++) {
    result += RoundUpToMultipleOf8(parameter_size_[i]);
  }
  return result;
}

bool MessageWriter::parameter_is_used(ParameterDescriptor parameter) const {
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

bool MessageWriter::parameter_is_used(int index) const {
  SystemCallDescriptor syscall(sysno_);
  ParameterDescriptor parameter = syscall.parameter(index);
  return parameter_is_used(parameter);
}

size_t MessageWriter::ParameterSize(ParameterDescriptor parameter) const {
  SystemCallDescriptor syscall(sysno_);

  // Return a size of zero for unused parameters.
  if (!parameter_is_used(parameter)) {
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
    return parameters_[parameter.bounding_parameter().index()] *
           parameter.element_size();
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
    header->error_number = error_number_;
  }

  // Write each parameter value into the buffer.
  size_t next_offset = sizeof(MessageHeader);

  SystemCallDescriptor syscall(sysno_);
  for (int i = 0; i < kParameterMax; i++) {
    ParameterDescriptor parameter = syscall.parameter(i);
    if (!parameter_is_used(parameter)) {
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
