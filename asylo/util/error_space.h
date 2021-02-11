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

#ifndef ASYLO_UTIL_ERROR_SPACE_H_
#define ASYLO_UTIL_ERROR_SPACE_H_

#include <string>
#include <type_traits>
#include <unordered_map>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/util/error_codes.h"

// This file, along with the associated cc file, defines the basic
// infrastructure for error-spaces that could be used with the
// ::asylo::Status class. The files also provide implementation of the
// canonical Google error space.

namespace asylo {
namespace error {

// Name of the canonical error space.
static constexpr char kCanonicalErrorSpaceName[] =
    "::asylo::error::GoogleErrorSpace";

// Forward declaration of abstract class ErrorSpace. This class acts as the base
// class for all error-space implementations.
class ErrorSpace;

/// \cond Internal
/// ErrorSpaceAdlTag is a zero-byte template struct that is used for invoking
/// the correct implementation of GetErrorSpace() and related methods.
template <typename EnumT>
struct ErrorSpaceAdlTag {
  // Make sure that error spaces can only be associated with enum types.
  static_assert(std::is_enum<EnumT>::value,
                "Cannot associate an error space with a non-enum type");
};

// The error_enum_traits class is used to determine whether the template
// arugument EnumT has an error-space associated with it, and to retrieve a
// singleton pointer to it, if one exists.
//
// This class uses some SFINAE techniques to determine the existence of an error
// space. While these techniques add some code complexity, it is expected that
// the added complexity is worth the benefit of compile-time error detection.
template <typename EnumT>
struct error_enum_traits {
 private:
  // TestErrorSpaceBinding is a function declaration that is used for statically
  // determining if a particular enum has an error-space associated with it.
  // Two function prototypes are defined, of which the compiler picks the most
  // restrictive one that applies.
  //
  // The first prototype is a more restrictive one, as it applies only to enum
  // types that have an error space associated with them (an enum type T is
  // considered to have an error space associated with it if and only if
  // ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<T>) is defined).
  //
  // The second prototype applies to all types, and hence is less restrictive.
  // The compiler will pick this prototype only if it is unable to pick the
  // first prototype.

  // Restrictive prototype.
  template <typename EnumU>
  static auto TestErrorSpaceBinding(ErrorSpace const *space)
      -> decltype(space = GetErrorSpace(ErrorSpaceAdlTag<EnumU>()),
                  std::true_type());

  // Non-restrictive prototype.
  template <typename EnumU>
  static auto TestErrorSpaceBinding(...) -> std::false_type;

  // Returns the error space associated with ErrorSpaceAdlTag template
  // specialization Tag.
  template <typename Tag>
  static ErrorSpace const *get_error_space(Tag tag, std::true_type t) {
    return GetErrorSpace(tag);
  }

  // Placeholder implementation designed to provide a meaningful compile-time
  // error for types that do not have an error space associated them.
  //
  // Note that although this definition of get_error_space() is a valid
  // candidate when TruthType is std::true_type, the compiler will choose the
  // definition above because it is more restrictive.
  template <typename Tag, typename TruthType>
  static ErrorSpace const *get_error_space(Tag tag, TruthType truth_type) {
    static_assert(TruthType::value,
                  "No error-space binding found for template parameter EnumT, "
                  "Make sure that GetErrorSpace(ErrorSpaceAdlTag<EnumT>) is "
                  "defined");
    return nullptr;
  }

 public:
  using error_space_binding_type = decltype(TestErrorSpaceBinding<EnumT>(0));

  static ErrorSpace const *get_error_space() {
    return get_error_space(ErrorSpaceAdlTag<EnumT>(),
                           error_space_binding_type());
  }
};
/// \endcond

/// All implementations of error spaces are derived from this abstract class.
/// \related GoogleErrorSpace
///
/// At a conceptual level, an ErrorSpace provides a mechanism for classifying
/// error codes into distinct categories and mapping those errors to
/// human readable strings. It also provides a mechanism for converting error
/// codes from arbitrary error spaces to the Google canonical error space.
///
/// At the implementation level, an error space consists of an error code enum
/// and an associated implementation of the abstract ErrorSpace interface. The
/// ErrorSpace interface declares three pure virtual methods. An ErrorSpace
/// interface implementation is bound to the error code enum via a compile-time
/// polymorphic function GetErrorSpace(), which can be used to retrieve a
/// singleton pointer to the error space associated with a particular enum.
///
/// Thus, to implement a new error space, the implementer must provide three
/// components:
///   1. An enum type that is not associated with any current ErrorSpace
///      implementation.
///   2. An implementation of the ErrorSpace interface.
///   3. An implementation of an appropriately-typed GetErrorSpace() function.
///
/// The error-space library maintains a global map of singletons for all the
/// error-space implementations loaded into the current address space. This map
/// can be queried to retrieve singleton pointers associated with a given name
/// using the ErrorSpace::Find(const string &name) method. To enable seamless
/// bookkeeping of such singletons, the error-space infrastructure defines an
/// intermediate template class called ErrorSpaceImplementationHelper, which is
/// derived from the ErrorSpace abstract class. Any error-space implementation
/// derived from this class is automatically tracked in the
/// error-space singleton global map. The helper class also provides a
/// std::unordered_map-based implementation of the SpaceName() and String()
/// methods, and as a result, error-space implementations derived from this
/// class do not need to provide their own implementation of these methods. It
/// is strongly recommended that all error-space implementations be derived from
/// the ErrorSpaceImplementationHelper. While it is possible to correctly
/// implement an error space without deriving from this class, such an
/// implementation will have to be aware of the error-space infrastructure, and
/// consequently, will be fragile.
///
/// Below is an example of implementing a new enum `Foo`, and associating it
/// with the ErrorSpace implementation `FooErrorSpace`.
///
/// First, define the enum type.
/// ```
/// enum Foo {
///   OK = 0,  // A value of 0 must always map to OK status in the error space.
///   ...
/// };
/// ```
/// Next implement the `FooErrorSpace` class by deriving it from
/// `ErrorSpaceImplementationHelper<FooErrorSpace>`.
/// ```
/// class FooErrorSpace : public ErrorSpaceImplementationHelper<FooErrorSpace> {
///  public:
///   using code_type = Foo;  // Error-space implementation must define the
///                           // code_type type-alias that aliases to the
///                           // underlying enum.
///   // No need to provide implementation of ErrorSpace interface, as
///   // ErrorSpaceImplementationHelper<FooErrorSpace> provides such
///   // implementation.
///
///   friend ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<Foo> tag);
///  private:
///
///   FooErrorSpace() : ErrorSpaceImplementationHelper<FooErrorSpace>{
///       "FooErrorSpace"} {
///    AddTranslationMapEntry(...);
///     ...
///   }
/// };
/// ```
/// Finally, bind the ErrorSpace implementation to the enum by defining
/// appropriate GetErrorSpace() function.
/// ```
/// ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<Foo> tag) {
///   // Must return a singleton pointer of FooErrorSpace
///   ...
/// }
/// ```
/// See GoogleErrorSpace for an example implementation.
class ErrorSpace {
 public:
  ErrorSpace() = default;
  ErrorSpace(const ErrorSpace &other) = delete;
  virtual ~ErrorSpace() = default;
  ErrorSpace &operator=(const ErrorSpace &other) = delete;

  /// Gets a name that uniquely identifies the error space.
  /// \return A uniquely identifying name for the ErrorSpace.
  virtual std::string SpaceName() const = 0;

  /// Gets a string that describes the error code within the space.
  /// \param code The error code to interpret within the error space.
  /// \return A description for the input code.
  virtual std::string String(int code) const = 0;

  /// Converts `code` to an appropriate value in the GoogleError enum.
  /// \param code The error code in this error space to convert to GoogleError.
  /// \return The GoogleError interpretation of `code`.
  virtual GoogleError GoogleErrorCode(int code) const = 0;

  /// Finds and returns an ErrorSpace singleton pointer whose SpaceName()
  /// equals `name`.
  /// \param name The name to search for.
  /// \return A singleton pointer to an ErrorSpace on success, nullptr on
  ///         failure.
  static ErrorSpace const *Find(const std::string &name);
};

/// \cond Internal
namespace error_internal {

// Namer object for the ErrorSpace base class. Used for creating an ErrorSpace
// static map.
struct ErrorSpaceNamer {
  std::string operator()(const ErrorSpace &space) { return space.SpaceName(); }
};

// Static map providing a mapping from error-space name string to an error-space
// singleton pointer.
class AsyloErrorSpaceStaticMap
    : public ::asylo::StaticMap<AsyloErrorSpaceStaticMap, const ErrorSpace,
                                ErrorSpaceNamer> {};

}  // namespace error_internal
/// \endcond

/// An intermediate template class that to help define an ErrorSpace subclass.
/// ErrorSpaceImplementationHelper automatically creates and inserts a singleton
/// instance of `ErrorSpaceT` into the global error-space singleton map. It is
/// customary to derive the class `ErrorSpaceT` from
/// `ErrorSpaceImplementationHelper<ErrorSpaceT>` to ensure correct management
/// of the map.
template <typename ErrorSpaceT>
class ErrorSpaceImplementationHelper : public ErrorSpace {
 protected:
  /// Constructs an ErrorSpaceImplementationHelper and registers it as
  /// `space_name`.
  ///
  /// \param space_name The name that ErrorSpace::Find() will use to fetch the
  ///        singleton instance of this ErrorSpace.
  /// \param default_error_string The result for String() for an unrecognized
  ///        error code.
  explicit ErrorSpaceImplementationHelper(
      const std::string &space_name,
      const std::string &default_error_string = "Unrecognized Code")
      : space_name_{space_name}, default_error_string_{default_error_string} {
    // Passing the address of |inserter_| to DoNotOptimize() forces the compiler
    // to instantiate the member variable.
    DoNotOptimize(&inserter_);
  }

  /// Adds an interpretation of an error code as both a string and GoogleError.
  ///
  /// \param code The error code to interpret.
  /// \param error_string The interpretation String() will return for `code`.
  /// \param google_error_code The most apt GoogleError to assign to `code`.
  void AddTranslationMapEntry(int code, const std::string &error_string,
                              GoogleError google_error_code) {
    CHECK(code_translation_map_
              .emplace(code, std::pair<std::string, GoogleError>(
                                 error_string, google_error_code))
              .second)
        << "Duplicate map key: " << code;
  }

  std::string SpaceName() const override { return space_name_; }

  std::string String(int code) const override {
    auto it = code_translation_map_.find(code);
    if (it == code_translation_map_.cend()) {
      if (code == 0) {
        return "OK";
      }
      return absl::StrFormat("%s (%d)", default_error_string_, code);
    }
    return it->second.first;
  }

  GoogleError GoogleErrorCode(int code) const override {
    if (code == 0) {
      // Error code value of zero must map to GoogleError::OK.
      return GoogleError::OK;
    }
    auto it = code_translation_map_.find(code);
    if (it == code_translation_map_.cend()) {
      return GoogleError::UNKNOWN;
    }
    return it->second.second;
  }

 private:
  using InserterType = error_internal::AsyloErrorSpaceStaticMap::ValueInserter;
  InserterType *DoNotOptimize(InserterType *inserter) { return inserter; }
  static InserterType inserter_;
  // Since ErrorSpace is used in trusted primitives layer where system calls may
  // not be available, avoid usage of absl containers which may make system
  // calls.
  std::unordered_map<int, std::pair<std::string, GoogleError>>
      code_translation_map_;
  const std::string space_name_;
  const std::string default_error_string_;
};

/// \cond Internal
// Instantiate inserter_ with a singleton pointer of |ErrorSpaceT| so that the
// singleton pointer gets inserted into the global map.
template <typename ErrorSpaceT>
error_internal::AsyloErrorSpaceStaticMap::ValueInserter
    ErrorSpaceImplementationHelper<ErrorSpaceT>::inserter_(
        GetErrorSpace(ErrorSpaceAdlTag<typename ErrorSpaceT::code_type>()));
/// \endcond

/// Binds the class GoogleErrorSpace to the #GoogleError enum.
ErrorSpace const *GetErrorSpace(
    ErrorSpaceAdlTag<::asylo::error::GoogleError> tag);

/// Binds the class GoogleErrorSpace to the #absl::StatusCode enum.
ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<::absl::StatusCode> tag);

/// The implementation of the ErrorSpace interface for the GoogleError canonical
/// error space.
class GoogleErrorSpace
    : public ErrorSpaceImplementationHelper<GoogleErrorSpace> {
 public:
  using code_type = GoogleError;

  GoogleErrorSpace(const GoogleErrorSpace &other) = delete;
  ~GoogleErrorSpace() override = default;
  GoogleErrorSpace &operator=(const GoogleErrorSpace &other) = delete;

  /// Gets the singleton instance of GoogleErrorSpace.
  /// \return The one instance of GoogleErrorSpace.
  static ErrorSpace const *GetInstance() {
    static ErrorSpace const *instance = new GoogleErrorSpace();
    return instance;
  }

 private:
  GoogleErrorSpace();
};

}  // namespace error
}  // namespace asylo

#endif  // ASYLO_UTIL_ERROR_SPACE_H_
