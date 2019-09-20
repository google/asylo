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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_METADATA_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_METADATA_H_

#include "absl/strings/string_view.h"

namespace asylo {
namespace system_call {

// This file defines an interface to a collection of Linux x86-64 ABI system
// calls descriptions.

// Maximum number of parameters expected by a system call.
constexpr int kParameterMax = 6;

// A record describing a system call parameter.
class ParameterDescriptor {
 public:
  // Constructs a null ParameterDescriptor.
  ParameterDescriptor() : sysno_(-1), index_(-1) {}

  // Constructs a descriptor for a parameter specified by its system call number
  // and index into the parameter list. If that pair is invalid, or has no entry
  // in the descriptor tables, an invalid descriptor is constructed.
  ParameterDescriptor(int sysno, int index) : sysno_(sysno), index_(index) {}

  // Returns true if this descriptor refers to a valid system call parameter
  // with a descriptor table entry.
  bool is_valid() const;

  // Returns the index of this parameter into the parameters list.
  int index() const { return index_; }

  // Returns the name of this parameter, or nullptr if this descriptor is
  // invalid.
  absl::string_view name() const;

  // Returns the type of this parameter as a string, or nullptr if this
  // descriptor is invalid.
  absl::string_view type() const;

  // Returns true if this parameter is a pointer.
  bool is_pointer() const;

  // Returns true if this parameter is a constant.
  bool is_const() const;

  // Returns true if this parameter is a void pointer.
  bool is_void_ptr() const;

  // Returns true if this parameter is a pointer to a fixed-size value.
  bool is_fixed() const;

  // Returns true if this parameter is a pointer to a bounded buffer.
  bool is_bounded() const;

  // Returns the descriptor for the parameter which describes the size of this
  // parameter in bytes, or an invalid descriptor if this is not a bounded
  // parameter.
  ParameterDescriptor bounding_parameter() const;

  // Returns true if this parameter is a pointer to a null-terminated string.
  bool is_string() const;

  // Returns true if this parameter is passed "in" to the system call.
  bool is_in() const;

  // Returns true if this parameter is passed "out" to the system call.
  bool is_out() const;

  // Returns true if this parameter is a scalar value.
  bool is_scalar() const;

  // Returns true if this parameter is a signed scalar value.
  bool is_signed() const;

  // Returns true if this parameter is an unsigned scalar value.
  bool is_unsigned() const;

  // Returns the size of this parameter. Depending on the values of the other
  // flags and whether this parameter has a fixed or dynamic size, the meaning
  // of the return value varies. For scalar parameters or pointers to fixed size
  // buffers, a size in bytes is returned. For bounded parameters, the index of
  // the bounding parameter is returned. For string parameters, zero is
  // returned.
  size_t size() const;

  // Returns the element size or stride used to determine the size of a buffer
  // of a certain type. For non-bounded parameters, and for bounded parameters
  // of type void* char* etc., element_size is always 1. For other bounded
  // parameters, element_size is the size of the type of array represented by
  // the buffer.
  size_t element_size() const;

  // Returns true is this parameter is a constant string copied into the kernel.
  bool in_string() const;

 private:
  bool test_flag(uint32_t flag) const;

  const int sysno_;
  const int index_;
};

// A record describing a system call.
class SystemCallDescriptor {
 public:
  // Constructs a descriptor for a system call by its number. If `sysno` is
  // invalid or has no entry in the descriptor tables, an invalid descriptor is
  // constructed.
  explicit SystemCallDescriptor(int sysno) : sysno_(sysno) {}

  // Returns true if this descriptor refers to a valid system call with a
  // descriptor table entry.
  bool is_valid() const;

  // Returns the name of this system call, or a null string_view if this
  // descriptor is invalid.
  absl::string_view name() const;

  // Returns the number of parameters expected by this system call, or -1 if
  // this descriptor is invalid.
  int parameter_count() const;

  // Returns a descriptor for the parameter at offset `index` into the parameter
  // list.
  ParameterDescriptor parameter(int index) const;

 private:
  const int sysno_;
};

// The largest system call value for which metadata is available.
int LastSystemCall();

}  // namespace system_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_METADATA_H_
