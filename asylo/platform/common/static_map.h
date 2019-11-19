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

#ifndef ASYLO_PLATFORM_COMMON_STATIC_MAP_H_
#define ASYLO_PLATFORM_COMMON_STATIC_MAP_H_

// The StaticMap template can be used to safely create a static map that holds
// instances of a value type T.
//
// Proper, safe usage of StaticMap requires that the following constraints are
// met:
//
//   * A static map may contain at most one instance of a derived type.
//   * A derived type of T must provide a default constructor.
//   * The constructor for a derived type of T must not depend on any
//     dynamically-initialized global or static state.
//
// Consider two classes, Base and Derived, where Derived is a subclass of Base.
// The following is an example usage of this template using Base and Derived:
//
//   // base.h
//
//   class Base {
//     ...
//     virtual void Foo() const {
//       std::cout << "Base" << std::endl;
//     }
//   };
//
//   DEFINE_STATIC_MAP_OF_BASE_TYPE(BaseMap, Base)
//
//   // derived.h
//
//   #include "base.h"
//
//   class Derived {
//     ...
//     void Foo() const override {
//       std::cout << "Derived" << std::endl;
//     }
//   };
//
//   // derived.cc
//
//   #include "derived.h"
//
//   SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(BaseMap, Derived)
//
// The static map can be used in some other file:
//
//   // main.cc
//
//   #include "derived.h"
//   ...
//
//   int main() {
//     auto element = BaseMap::GetValue("Derived");
//     element->Foo();                                     // prints "Derived"
//     size_t size = BaseMap::GetSize();                   // size == 1
//     return 0;
//   }
//
// By default, the StaticMap template requires a specialization of the Namer
// template to exist for the value type T stored in the map. This template is
// used to generate unique keys for elements added to the map. A specialization
// of this template defines a functor that, given an instance of T, returns a
// string that uniquely identifies the particular derived type of that object.
// This can be achieved by making a call to some virtual method of T that is
// defined for each derived type.
//
// A specialization of the Namer template must be injected into the
// ::asylo namespace. For the Base example used above, this would
// look as follows:
//
//   // base.h
//
//   template<>
//   struct Namer<Base> {
//     string operator()(const Base &b) {
//       // Call some virtual function provided by Base...
//     }
//   };
//
// Alternatively, a functor or callable type satisfying the requirements of the
// Namer template or a specialization of the Namer template itself may be passed
// when creating the map. See the comment for DEFINE_STATIC_MAP_OF_BASE_TYPE for
// more details. Continuing the previous example, this could be done as follows:
//
//   // base.h
//
//   struct BaseNamer {
//     string operator()(const Base &b) { ... }
//   };
//
//   DEFINE_STATIC_MAP_OF_BASE_TYPE(BaseMap, Base, BaseNamer)

#include <string>
#include <type_traits>
#include <unordered_map>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/static_map_internal.h"

namespace asylo {

// Creates a new static map |MapName| that holds instances of |ValueType|.
// This macro takes three arguments, where the last argument is optional. If
// specified, the last argument must be a functor or a callable type that
// satisfies the following:
//   * Accepts a single parameter of type |ValueType|.
//   * Returns a value of type string that uniquely identifies the derived
//     type. This value can be used to query the map for the element.
//   * May be a specialization of the Namer template defined below.
//
// This macro must be placed in a header file.
#define DEFINE_STATIC_MAP_OF_BASE_TYPE(MapName, ValueType, ...) \
  class MapName                                                 \
      : public ::asylo::StaticMap<MapName, ValueType, ##__VA_ARGS__> {};

// Adds an instance of |SubclassType| to the static map |MapName|. The only
// valid use of this macro is in the .cc file for |SubclassType|.
#define SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(MapName, SubclassType) \
  namespace {                                                       \
  MapName::ValueInserter MapName##SubclassType(new SubclassType()); \
  }

// Namer is a functor that, given an instance of a derived type of T, returns a
// unique identifier for the derived type.
template <class T>
struct Namer;

// StaticMap is a static map holding instances of types derived from the value
// type T. At most one instance of a particular type is allowed in the map, and
// a unique key for each element is generated using N.
//
// The map used internally is dynamically allocated and is never destroyed
// during the lifetime of the program (i.e. it is intentionally leaked). Since
// StaticMap is used in the trusted the primitives interface where system calls
// might not be available, we use std::unordered_map instead of
// absl::flat_hash_map to prevent unsafe system calls made by absl based
// containers.
template <class MapName, class T, class N = Namer<T>>
class StaticMap {
 public:
  using value_iterator = internal::ValueIterator<
      T, typename std::unordered_map<std::string, T *>::iterator>;
  using const_value_iterator = internal::ValueIterator<
      const T, typename std::unordered_map<std::string, T *>::const_iterator>;

  // ValueInserter is a helper class whose constructor inserts a pointer to an
  // instance of T into the static map.
  class ValueInserter {
   public:
    explicit ValueInserter(T *value) ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
#ifndef __ASYLO__
      static_assert(
          std::is_trivially_default_constructible<N>::value,
          "StaticMap requires a template parameter N that is trivially default "
          "constructible");
#endif  // __ASYLO__

      absl::MutexLock lock(&StaticMap::mu_);

      // First-time map initialization.
      StaticMap::Initialize();

      // Retrieve a unique string identifier for this object that can be used as
      // a key in the map.
      std::string key = StaticMap::namer_(*value);
      if (!StaticMap::map_->emplace(key, value).second) {
        LOG(FATAL) << "Adding duplicate key " << key << " to static map";
      }
    }
  };

  // ValueCollection is a zero-byte helper class that represents the collection
  // of values stored in a static map. This class defines various iterator
  // generators that enable iterating over the collection of values.
  class ValueCollection {
   public:
    using iterator = StaticMap::value_iterator;
    using const_iterator = StaticMap::const_value_iterator;

    ValueCollection() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);

      // First-time map initialization.
      StaticMap::Initialize();
    }

    iterator begin() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);
      return iterator(StaticMap::map_->begin());
    }
    const_iterator begin() const ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);
      return const_iterator(StaticMap::map_->cbegin());
    }
    const_iterator cbegin() const ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);
      return const_iterator(StaticMap::map_->cbegin());
    }
    iterator end() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);
      return iterator(StaticMap::map_->end());
    }
    const_iterator end() const ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);
      return const_iterator(StaticMap::map_->cend());
    }
    const_iterator cend() const ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
      absl::MutexLock lock(&StaticMap::mu_);
      return const_iterator(StaticMap::map_->cend());
    }
  };

  // Returns a ValueCollection object representing the values stored in the
  // static map.
  static ValueCollection Values() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
    return ValueCollection();
  }

  static value_iterator value_begin() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
    return Values().begin();
  }
  static value_iterator value_end() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
    return Values().end();
  }
  static const_value_iterator value_cbegin()
      ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
    return Values().cbegin();
  }
  static const_value_iterator value_cend() ABSL_LOCKS_EXCLUDED(StaticMap::mu_) {
    return Values().cend();
  }

  // Returns the value_iterator pointing to the T value associated with |key|.
  // Returns value_end() if |key| is not present.
  static value_iterator GetValue(const std::string &key) {
    absl::MutexLock lock(&StaticMap::mu_);

    // First-time map initialization.
    Initialize();

    return value_iterator(StaticMap::map_->find(key));
  }

  static size_t Size() {
    absl::MutexLock lock(&StaticMap::mu_);

    // First-time map initialization.
    Initialize();

    return StaticMap::map_->size();
  }

 private:
  static void Initialize() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    if (map_ == nullptr) {
      map_ = new std::unordered_map<std::string, T *>();
    }
  }
  static std::unordered_map<std::string, T *> *map_ ABSL_GUARDED_BY(mu_)
      ABSL_PT_GUARDED_BY(mu_);
  static absl::Mutex mu_;
  static N namer_;
};

template <class MapName, class T, class N>
std::unordered_map<std::string, T *> *StaticMap<MapName, T, N>::map_ = nullptr;

template <class MapName, class T, class N>
absl::Mutex StaticMap<MapName, T, N>::mu_;

template <class MapName, class T, class N>
N StaticMap<MapName, T, N>::namer_;

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_STATIC_MAP_H_
