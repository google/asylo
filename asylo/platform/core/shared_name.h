/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_PLATFORM_CORE_SHARED_NAME_H_
#define ASYLO_PLATFORM_CORE_SHARED_NAME_H_

#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>

#include "asylo/platform/common/hash_combine.h"
#include "asylo/platform/core/shared_name_kind.h"

namespace asylo {

/// A name shared between trusted and untrusted code.
///
/// A tagged string class representing a name shared between trusted and
/// untrusted code.
class SharedName {
 public:
  /// Constructs an invalid, null SharedName.
  SharedName() = default;

  /// Constructs a SharedName.
  ///
  /// \param kind The kind of the name's resource domain
  /// \param name The SharedName's name that should be unique within its kind.
  SharedName(SharedNameKind kind, const std::string &name)
      : kind_(kind), name_(name) {}

  /// The SharedName's kind of resource name domain.
  ///
  /// \returns The resource domain of the name.
  SharedNameKind kind() const { return kind_; }

  /// The SharedName's name within its kind.
  ///
  /// \returns The string value of the name within its domain.
  const std::string &name() const { return name_; }

  /// Constructs a SharedName with kind kAddressName.
  static SharedName Address(const std::string &name) {
    return SharedName(kAddressName, name);
  }

  /// Constructs a SharedName with kind kMemBlockName.
  static SharedName MemBlock(const std::string &name) {
    return SharedName(kMemBlockName, name);
  }

  /// Constructs a SharedName with kind kSocketName.
  static SharedName Socket(const std::string &name) {
    return SharedName(kSocketName, name);
  }

  /// Constructs a SharedName with kind kTimerName.
  static SharedName Timer(const std::string &name) {
    return SharedName(kTimerName, name);
  }

  struct Hash : std::unary_function<SharedName, size_t> {
    size_t operator()(const SharedName &name) const {
      return HashCombine<std::string>(std::hash<int>()(name.kind_), name.name_);
    }
  };

  struct Eq : std::binary_function<SharedName, SharedName, bool> {
    bool operator()(const SharedName &lhs, const SharedName &rhs) const {
      return (lhs.kind_ == rhs.kind_) && (lhs.name_ == rhs.name_);
    }
  };

 private:
  SharedNameKind kind_;
  std::string name_;
};

inline std::ostream &operator<<(std::ostream &os, const SharedName &name) {
  switch (name.kind()) {
    case kUnspecifiedName:
      os << "kUnspecifiedName";
      break;
    case kAddressName:
      os << "kAddressName";
      break;
    case kSocketName:
      os << "kSocketName";
      break;
    case kTimerName:
      os << "kTimerName";
      break;
    case kMemBlockName:
      os << "kMemBlockName";
      break;
    default:
      abort();
  }
  return os << "::" << name.name();
}

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_SHARED_NAME_H_
