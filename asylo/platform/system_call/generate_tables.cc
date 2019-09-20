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

#include <iostream>
#include <map>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "asylo/platform/system_call/syscalls.inc"

// This file implements a code generation tool built with a native Linux
// toolchain and run on a native Linux host. The generator takes a list of Linux
// system calls defined in an include file "syscalls.inc," and emits a number of
// tables describing the parameter types and other features of those system call
// as C++ code. Trusted code run inside an enclave can then build against the
// generated tables to obtain access to a description of the system interface on
// the host. This data may then be used to drive automated serialization of
// system calls across the enclave boundary.

// An entry in a table of system call descriptions.
struct SystemCallDescription {
  std::string name;
  int parameter_count;
  size_t parameter_index;
};

// An entry in a table of system call parameter descriptions.
struct ParameterDescription {
  std::string syscall;
  int index;
  std::string name;
  std::string flags;
  std::string type;
  size_t size;  // Denotes the size in bytes of a parameter for a non-bounded
                // parameter. For a bounded buffer parameter, it denotes the
                // relative position of the binding parameter from the first
                // parameter to the syscall.
  size_t
      element_size;  // Denotes the element size (or stride) for a bounded
                     // buffer parameter. For a non-bounded parameter or a
                     // buffer of type void* or char*, element_size is always 1.
};

// Flag describing a parameter passing convention.
enum ConventionFlag { kIn = 1, kOut = 2 };

// Returns a table mapping a {system call, parameter} pair to a bounding
// parameter position (relative to the first parameter of the system call).
absl::flat_hash_map<std::pair<std::string, std::string>, int> *BoundsTable() {
  static auto *bounds_table =
      new absl::flat_hash_map<std::pair<std::string, std::string>, int>{
          PARAMETER_BOUNDS_INIT};
  return bounds_table;
}

// Returns a table mapping a {system call, parameter} pair to a {bounding
// parameter position (relative to index), parameter type size} pair.
absl::flat_hash_map<std::pair<std::string, std::string>, std::pair<int, int>>
    *LengthsTable() {
  static auto *lengths_table =
      new absl::flat_hash_map<std::pair<std::string, std::string>,
                              std::pair<int, int>>{PARAMETER_LENGTHS_INIT};
  return lengths_table;
}

// Returns a table mapping a {system call, parameter} pair to a bit mask of
// ConventionFlag values.
absl::flat_hash_map<std::pair<std::string, std::string>, int>
    *ConventionTable() {
  static auto *convention_table =
      new absl::flat_hash_map<std::pair<std::string, std::string>, int>{
          PARAMETER_CONVENTIONS_INIT};
  return convention_table;
}

// Returns a table mapping a {system call, parameter} pair to the 'count'
// annotation for that parameter.
absl::flat_hash_map<std::pair<std::string, std::string>, int> *CountsTable() {
  static auto *counts_table =
      new absl::flat_hash_map<std::pair<std::string, std::string>, int>{
          PARAMETER_COUNTS_INIT};
  return counts_table;
}

// Format a list of static properties of a type T as a set of flags.
template <typename T>
std::string TypeFlags(const std::string &syscall, const std::string &name) {
  std::vector<std::string> flags;

  if (std::is_pointer<T>()) {
    flags.push_back("kPointer");
  } else if (std::is_integral<T>()) {
    flags.push_back("kScalar");
    // For scalar parameters, store whether this parameter is signed.
    if (std::is_signed<T>()) {
      flags.push_back("kSigned");
    } else if (std::is_unsigned<T>()) {
      flags.push_back("kUnsigned");
    }
  }

  // Test whether this parameter has an explicitly specified calling convention.
  {
    auto it = ConventionTable()->find({syscall, name});
    if (it != ConventionTable()->end()) {
      if (it->second & kIn) {
        flags.push_back("kIn");
      }
      if (it->second & kOut) {
        flags.push_back("kOut");
      }
    } else {
      // Otherwise, scalar parameters are marked as kIn, constant pointer
      // parameters default to "kIn," and mutable parameters default to "kIn |
      // kOut".
      if (std::is_pointer<T>()) {
        using pointee_type = typename std::remove_pointer<T>::type;

        if (std::is_void<pointee_type>::value) {
          flags.push_back("kVoidPtr");
        }

        if (std::is_const<pointee_type>::value) {
          flags.push_back("kConst");
          flags.push_back("kIn");
        } else {
          flags.push_back("kIn");
          flags.push_back("kOut");
        }
      } else {
        // Scalar parameters are always marked "kConst" and "kIn."
        flags.push_back("kConst");
        flags.push_back("kIn");
      }
    }
  }

  // Test whether this parameter has an explicitly specified size.
  {
    auto it_bounds = BoundsTable()->find({syscall, name});
    auto it_lengths = LengthsTable()->find({syscall, name});
    if (it_bounds != BoundsTable()->end() ||
        it_lengths != LengthsTable()->end()) {
      flags.push_back("kBounded");
    } else {
      // Otherwise, pointer parameters are interpreted as referring to exactly
      // one value, with the exception of "const char *" which defaults to
      // kString and "void *" which defaults to being copied as a scalar value.
      if (std::is_pointer<T>()) {
        if (std::is_same<T, const char *>()) {
          flags.push_back("kString");
        } else if (std::is_void<typename std::remove_pointer<T>::type>::value) {
          flags.push_back("kScalar");
        } else {
          flags.push_back("kFixed");
        }
      }
    }
  }

  return absl::StrJoin(flags, " | ");
}

// As sizeof(), but with a specialization allowing TypeSize<void>() to return 0.
template <typename T>
constexpr size_t TypeSize() {
  return sizeof(T);
}

template <>
constexpr size_t TypeSize<void>() {
  return 0;
}

template <>
constexpr size_t TypeSize<const void>() {
  return 0;
}

// Returns the encoding size of a type T.
template <typename T>
size_t EncodingSize(const std::string &syscall, const std::string &name) {
  // Check for an explicitly specified bound.
  {
    auto it_bounds = BoundsTable()->find({syscall, name});
    if (it_bounds != BoundsTable()->end()) {
      if (!std::is_pointer<T>()) {
        std::cerr << absl::StreamFormat(
                         "Error: Scalar parameter \"%s\" of system call \"%s\" "
                         "may not be annotated with a bounding parameter.",
                         syscall, name)
                  << std::endl;
        exit(1);
      }
      return it_bounds->second;  // Return the offset to binding param.
    }
    auto it_lengths = LengthsTable()->find({syscall, name});
    if (it_lengths != LengthsTable()->end()) {
      if (!std::is_pointer<T>()) {
        std::cerr << absl::StreamFormat(
                         "Error: Scalar parameter \"%s\" of system call \"%s\" "
                         "may not be annotated with a bounding parameter.",
                         syscall, name)
                  << std::endl;
        exit(1);
      }
      return it_lengths->second.first;  // Return the offset to binding param.
    }
  }

  // Check for an explicitly specified count.
  {
    size_t count;
    auto it = CountsTable()->find({syscall, name});
    if (it != CountsTable()->end()) {
      if (!std::is_pointer<T>()) {
        std::cerr << absl::StreamFormat(
                         "Error: Scalar parameter \"%s\" of system call \"%s\" "
                         "may not be annotated with an array element count.",
                         syscall, name)
                  << std::endl;
        exit(1);
      }
      count = it->second;
    } else {
      count = 1;
    }

    if (std::is_pointer<T>()) {
      // In the case of a pointer, we are interested in the size of the
      // pointee rather than the size of the pointer.
      using U = typename std::remove_pointer<T>::type;
      return TypeSize<U>() * count;
    }
  }

  // Otherwise this is a scalar type.
  return TypeSize<T>();
}

// Returns the type size to be used to determine the size of a bounded buffer.
template <typename T>
size_t ElementSize(const std::string &syscall, const std::string &name) {
  auto it_lengths = LengthsTable()->find({syscall, name});
  if (it_lengths != LengthsTable()->end()) {
    if (!std::is_pointer<T>()) {
      std::cerr << absl::StreamFormat(
                       "Error: Scalar parameter \"%s\" of system call \"%s\" "
                       "may not be annotated with an bounding parameter.",
                       syscall, name)
                << std::endl;
      exit(1);
    }
    return it_lengths->second.second;
  }
  return 1;
}

// Returns a table of system calls descriptions.
std::map<int, SystemCallDescription> *SystemCallTable() {
  static auto *system_calls =
      new std::map<int, SystemCallDescription>{SYSTEM_CALL_TABLE_INIT};
  return system_calls;
}

// Returns a table of parameter descriptions.
absl::flat_hash_map<int, ParameterDescription> *ParameterTable() {
  static auto *parameter_table =
      new absl::flat_hash_map<int, ParameterDescription>{PARAMETER_TABLE_INIT};
  return parameter_table;
}

// Emits a table of system call descriptions.
void EmitSystemCallTable(std::ostream *os) {
  // Write a table to the output stream as a C++ static data.

  if (SystemCallTable()->empty()) {
    std::cerr << "Expected at least one system call to be defined."
              << std::endl;
    abort();
  }

  int last = SystemCallTable()->rbegin()->first;

  *os << "const size_t kSystemCallTableSize = " << last + 1 << ";\n";
  *os << "\n";
  *os << "const SystemCallTableEntry kSystemCallTable[] = {\n";
  for (int i = 0; i <= last; i++) {
    auto it = SystemCallTable()->find(i);
    std::string name;
    int count;
    size_t index;
    if (it == SystemCallTable()->end()) {
      name = "nullptr";
      count = 0;
      index = 0;
    } else {
      name = absl::StrCat("\"", it->second.name, "\"");
      count = it->second.parameter_count;
      index = it->second.parameter_index;
    }
    *os << absl::StreamFormat("  /* %i */ {%s, %i, %i},\n", i, name, count,
                              index);
  }
  *os << "};\n";
}

// Emits a table of parameter descriptions.
void EmitParameterTable(std::ostream *os) {
  *os << "const ParameterTableEntry kParameterTable[] = {\n";
  for (size_t i = 0; i < ParameterTable()->size(); i++) {
    const ParameterDescription &desc = (*ParameterTable())[i];
    *os << absl::StreamFormat(
        "  /* %s:%i */ {\"%s\", \"%s\", %s, %llu, %llu},\n", desc.syscall,
        desc.index, desc.name, desc.type, desc.flags, desc.size,
        desc.element_size);
  }
  *os << "};\n";
}

int main(int argc, char **argv) {
  EmitSystemCallTable(&std::cout);
  std::cout << std::endl;
  EmitParameterTable(&std::cout);
  return 0;
}
