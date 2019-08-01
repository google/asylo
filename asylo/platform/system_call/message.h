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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_MESSAGE_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_MESSAGE_H_

#include <array>
#include <cstddef>
#include <string>

#include "absl/base/attributes.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/system_call/metadata.h"

namespace asylo {
namespace system_call {

// Serialized system call flag values.
enum MessageFlags : uint32_t {
  kSystemCallRequest = 0x1,
  kSystemCallResponse = 0x2
};

// Message magic number = "syscal\0".
constexpr uint64_t kMessageMagic = 0x1006c6163737973;

// Message header format. All values are little-endian.
struct MessageHeader {
  /* byte:  0 ..   7 */ uint64_t magic;                  // Magic number.
  /* byte:  8 ..  11 */ uint32_t flags;                  // Flags bitmap.
  /* byte: 12 ..  15 */ uint32_t sysno;                  // System call number.
  /* byte: 16 ..  23 */ uint64_t result;                 // System call result.
  /* byte: 24 ..  31 */ uint64_t error_number;           // System call errno.
  /* byte: 32 ..  79 */ uint64_t offset[kParameterMax];  // Parameter offset.
  /* byte: 80 .. 127 */ uint64_t size[kParameterMax];    // Parameter size.
} ABSL_ATTRIBUTE_PACKED;

static_assert(offsetof(MessageHeader, magic) == 0,
              "Unexpected layout for MessageHeader::size.");
static_assert(offsetof(MessageHeader, flags) == 8,
              "Unexpected layout for MessageHeader::flags.");
static_assert(offsetof(MessageHeader, sysno) == 12,
              "Unexpected layout for MessageHeader::sysno.");
static_assert(offsetof(MessageHeader, result) == 16,
              "Unexpected layout for MessageHeader::result.");
static_assert(offsetof(MessageHeader, error_number) == 24,
              "Unexpected layout for MessageHeader::error_number");
static_assert(offsetof(MessageHeader, offset) == 32,
              "Unexpected layout for MessageHeader::offset.");
static_assert(offsetof(MessageHeader, size) == 80,
              "Unexpected layout for MessageHeader::size.");
static_assert(sizeof(MessageHeader) % 8 == 0,
              "sizeof(MessageHeader) must be a multiple of 8 to ensure correct "
              "parameter alignment.");

// Read operations on a system call request or response message.
class MessageReader {
 public:
  // Constructs a MessageReader from an extent.
  explicit MessageReader(primitives::Extent extent) : extent_(extent) {}

  // Returns a pointer to the message header.
  const MessageHeader *header() const {
    return reinterpret_cast<const MessageHeader *>(extent_.data());
  }

  // Returns true is this message is a system call response.
  bool is_request() const { return header()->flags & kSystemCallRequest; }

  // Returns true is this message is a system call request.
  bool is_response() const { return header()->flags & kSystemCallResponse; }

  // Returns the system call encoded by the message.
  int sysno() const { return header()->sysno; }

  // Returns the result of the system call encoded by the message.
  uint64_t result() const { return header()->result; }

  // Returns the errno encoded by the message. The errno value is valid only if
  // result is -1.
  uint64_t error_number() const { return header()->error_number; }

  // Checks the validity of this message, returning an OK status on success.
  primitives::PrimitiveStatus Validate() const;

  // Returns true if the parameter at offset |index| into the parameter list is
  // used by this encoding.
  bool parameter_is_used(int index) const;

  // Interprets a message parameter as a pointer to a value of type T and
  // dereferences it.
  template <typename T>
  T parameter(int index) const {
    return *reinterpret_cast<const T *>(extent_.As<char>() + offset(index));
  }

  // Interprets a message parameter as a pointer to a value of type T and
  // returns it.
  template <typename T = const void *>
  T parameter_address(int index) const {
    return parameter_size(index) > 0
               ? reinterpret_cast<T>(extent_.As<char>() + offset(index))
               : T(0);
  }

  // Returns the size of the parameter for a parameter index, or 0 if that
  // parameter is not used by this encoding.
  size_t parameter_size(int index) const { return header()->size[index]; }

 private:
  // Returns the offset (in bytes) into the message buffer of the parameter at
  // the given `index` into the parameter list, or zero if this parameter is
  // null or not used by this encoding.
  size_t offset(int index) const { return header()->offset[index]; }

  // Returns a PrimitiveStatus indicating an invalid argument with a message
  // |reason|.
  primitives::PrimitiveStatus invalid_argument_status(
      const std::string &reason) const;

  // Checks the validity of this message header, returning an OK status on
  // success.
  primitives::PrimitiveStatus ValidateMessageHeader() const;

  // Returns true if the parameter into the parameters list is used by this
  // encoding.
  bool parameter_is_used(ParameterDescriptor parameter) const;

  // Returns true if the parameter size is correct.
  bool IsValidParameterSize(int index) const;

  primitives::Extent extent_;
};

// Write operations on a system call request or response message.
class MessageWriter {
 public:
  // Construct a response writer for a system call with a parameter list.
  static MessageWriter RequestWriter(
      int sysno, const std::array<uint64_t, kParameterMax> &parameters);

  // Construct a response writer for a system call with a parameter list.
  static MessageWriter ResponseWriter(
      int sysno, uint64_t result, uint64_t error_number,
      const std::array<uint64_t, kParameterMax> &parameters);

  // Returns the size of the configured message.
  size_t MessageSize() const;

  // Writes the message into a buffer, which must be at least `MessageSize()`
  // bytes long.
  bool Write(primitives::Extent *message) const;

 private:
  MessageWriter(int sysno, uint64_t result, uint64_t error_number,
                bool is_request,
                const std::array<uint64_t, kParameterMax> &parameters);

  // Returns true if the parameter into the parameters list is used by this
  // encoding.
  bool parameter_is_used(ParameterDescriptor parameter) const;

  // Returns true if the parameter at offset |index| into the parameters list is
  // used by this encoding.
  bool parameter_is_used(int index) const;

  // Returns the encoding size of a parameter.
  size_t ParameterSize(ParameterDescriptor parameter) const;

  bool is_request() const { return is_request_; }

  bool is_response() const { return !is_request_; }

  int sysno_;
  uint64_t result_;
  uint64_t error_number_;
  bool is_request_;
  const std::array<uint64_t, kParameterMax> parameters_;
  std::array<size_t, kParameterMax> parameter_size_;
};

// Formats a message as a human-readable string suitable for logging or
// debugging.
std::string FormatMessage(primitives::Extent extent);

}  // namespace system_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_MESSAGE_H_
