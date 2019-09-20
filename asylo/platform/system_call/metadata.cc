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

#include "asylo/platform/system_call/metadata.h"

#include <cstddef>
#include <cstdint>

namespace asylo {
namespace system_call {

namespace {

enum ParameterFlag : uint16_t {
  kIn = 1 << 0,        // Parameter copied "in" to the kernel.
  kOut = 1 << 1,       // Parameter copied "out" of the kernel.
  kUnsigned = 1 << 2,  // Signed scalar value.
  kSigned = 1 << 3,    // Unsigned scalar value.
  kPointer = 1 << 4,   // Pointer value.
  kVoidPtr = 1 << 5,   // Parameter is a void *.
  kConst = 1 << 6,     // Parameter is a constant.
  kScalar = 1 << 7,    // Scalar parameter passed by value.
  kString = 1 << 8,    // Pointer to null-terminated string.
  kFixed = 1 << 9,     // Pointer to fixed size object.
  kBounded = 1 << 10,  // Pointer to buffer bounded by a parameter value.
};

struct SystemCallTableEntry {
  const char *name;
  const uint8_t parameter_count;
  const size_t parameter_index;
};

struct ParameterTableEntry {
  const char *name;
  const char *type;
  const uint16_t flags;
  const uint32_t size;
  const uint32_t element_size;
};

// Include the metadata tables generated at build time.
#include "asylo/platform/system_call/generated_tables.inc"

// Returns the index of an entry into the parameter table. This routine does not
// bound check its input and assumes the passed parameters have already been
// validated.
size_t find_parameter_index(int sysno, int index) {
  return kSystemCallTable[sysno].parameter_index + index;
}

// Returns the flags bitmask for an entry in the parameter table. This routine
// does not bound check its input and assumes the passed parameters have already
// been validated.
size_t find_parameter_flags(int sysno, int index) {
  return kParameterTable[find_parameter_index(sysno, index)].flags;
}

}  // namespace

int LastSystemCall() { return kSystemCallTableSize - 1; }

bool SystemCallDescriptor::is_valid() const {
  return sysno_ >= 0 && sysno_ < kSystemCallTableSize &&
         kSystemCallTable[sysno_].name != nullptr;
}

absl::string_view SystemCallDescriptor::name() const {
  return is_valid() ? kSystemCallTable[sysno_].name : nullptr;
}

int SystemCallDescriptor::parameter_count() const {
  return is_valid() ? kSystemCallTable[sysno_].parameter_count : -1;
}

ParameterDescriptor SystemCallDescriptor::parameter(int index) const {
  return ParameterDescriptor{sysno_, index};
}

bool ParameterDescriptor::is_valid() const {
  SystemCallDescriptor syscall{sysno_};
  return syscall.is_valid() && index_ >= 0 &&
         index_ < syscall.parameter_count();
}

absl::string_view ParameterDescriptor::name() const {
  return is_valid() ? kParameterTable[find_parameter_index(sysno_, index_)].name
                    : nullptr;
}

absl::string_view ParameterDescriptor::type() const {
  return is_valid() ? kParameterTable[find_parameter_index(sysno_, index_)].type
                    : nullptr;
}

bool ParameterDescriptor::test_flag(uint32_t flag) const {
  return is_valid() && find_parameter_flags(sysno_, index_) & flag;
}

bool ParameterDescriptor::is_pointer() const { return test_flag(kPointer); }

bool ParameterDescriptor::is_scalar() const { return test_flag(kScalar); }

bool ParameterDescriptor::is_signed() const { return test_flag(kSigned); }

bool ParameterDescriptor::is_unsigned() const { return test_flag(kUnsigned); }

bool ParameterDescriptor::is_fixed() const { return test_flag(kFixed); }

bool ParameterDescriptor::is_bounded() const { return test_flag(kBounded); }

bool ParameterDescriptor::is_const() const { return test_flag(kConst); }

bool ParameterDescriptor::is_void_ptr() const { return test_flag(kVoidPtr); }

ParameterDescriptor ParameterDescriptor::bounding_parameter() const {
  return is_bounded() ? ParameterDescriptor(sysno_, size())
                      : ParameterDescriptor{};
}

bool ParameterDescriptor::is_string() const { return test_flag(kString); }

bool ParameterDescriptor::is_in() const { return test_flag(kIn); }

bool ParameterDescriptor::is_out() const { return test_flag(kOut); }

size_t ParameterDescriptor::size() const {
  return is_valid() ? kParameterTable[find_parameter_index(sysno_, index_)].size
                    : 0;
}

size_t ParameterDescriptor::element_size() const {
  return is_valid() ? kParameterTable[find_parameter_index(sysno_, index_)]
                          .element_size
                    : 0;
}

bool ParameterDescriptor::in_string() const {
  return is_in() && find_parameter_flags(sysno_, index_) & kString;
}

}  // namespace system_call
}  // namespace asylo
