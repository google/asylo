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

#ifndef ASYLO_UTIL_PROTO_ENUM_UTIL_H_
#define ASYLO_UTIL_PROTO_ENUM_UTIL_H_

#include <iterator>
#include <string>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_enum_reflection.h>
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"

namespace asylo {

// Returns a human-readable name for |enum_value|. ProtoEnumT must be a protobuf
// enum type.
//
// If |enum_value| is one of the enumerator values of ProtoEnumT, then
// ProtoEnumValueName() returns the name of the enumerator value. Otherwise,
// ProtoEnumValueName() returns the decimal representation of |enum_value|.
template <typename ProtoEnumT>
std::string ProtoEnumValueName(ProtoEnumT enum_value) {
  const google::protobuf::EnumValueDescriptor *value_descriptor =
      google::protobuf::GetEnumDescriptor<ProtoEnumT>()->FindValueByNumber(enum_value);
  if (value_descriptor == nullptr) {
    return std::to_string(enum_value);
  }

  return value_descriptor->name();
}

// Returns a human-readable, comma-delimited list of enum values for |range|.
// ProtoEnumValueRangeT must support begin and end forward iterators over a
// protobuf enum type.
//
// Individual enum value strings are determined using
// `ProtoEnumValueNamValueName`.
template <typename ProtoEnumValueRangeT>
std::string AllProtoEnumValueNames(const ProtoEnumValueRangeT &range) {
  using Iterator = decltype(std::begin(range));
  using EnumType = typename std::iterator_traits<Iterator>::value_type;
  return absl::StrFormat(
      "[%s]", absl::StrJoin(range, ", ", [](std::string *out, EnumType value) {
        out->append(ProtoEnumValueName(value));
      }));
}

// ProtoEnumRange is a type which provides the necessary functions to use
// range-based for loops over all possible values in a protobuf enumeration.
// Values are walked using the google::protobuf::EnumDescriptor, which enumerates all
// values in the same order they were defined in the .proto file.
//
// In C++, any class with begin() and end() functions satisifies the
// requirements of a range expression within a range-based for loop.
//
// Sample use:
//   for (EnumType e : ProtoEnumRange<EnumType>()) {
//      LOG(INFO) << e;
//   }
template <typename ProtoEnumT>
class ProtoEnumRange {
 public:
  class Iterator : public std::iterator<std::forward_iterator_tag, ProtoEnumT> {
   public:
    Iterator(const Iterator &) = default;
    Iterator& operator=(const Iterator &) = default;

    Iterator &operator++() {
      ++index_;
      return *this;
    }

    bool operator==(const Iterator &other) const {
      return index_ == other.index_;
    }

    bool operator!=(const Iterator &other) const { return !(*this == other); }

    ProtoEnumT operator*() const {
      auto enum_descriptor = google::protobuf::GetEnumDescriptor<ProtoEnumT>();
      auto value_descriptor = enum_descriptor->value(index_);
      return static_cast<ProtoEnumT>(value_descriptor->number());
    }

   private:
    friend class ProtoEnumRange;
    explicit Iterator(int index) : index_(index) {}
    int index_;
  };

  Iterator begin() { return Iterator(0); }

  Iterator end() {
    auto enum_descriptor = google::protobuf::GetEnumDescriptor<ProtoEnumT>();
    return Iterator(enum_descriptor->value_count());
  }
};

}  // namespace asylo

#endif  // ASYLO_UTIL_PROTO_ENUM_UTIL_H_
