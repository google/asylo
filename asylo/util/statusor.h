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

#ifndef ASYLO_UTIL_STATUSOR_H_
#define ASYLO_UTIL_STATUSOR_H_

#include <type_traits>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/config.h"
#include "absl/meta/type_traits.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "asylo/util/logging.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status.h"
#include "asylo/util/status_error_space.h"

namespace asylo {

#ifdef NDEBUG
ABSL_CONST_INIT extern const char kValueMoveConstructorMsg[];
ABSL_CONST_INIT extern const char kValueMoveAssignmentMsg[];
ABSL_CONST_INIT extern const char kValueOrDieMovedMsg[];
ABSL_CONST_INIT extern const char kStatusMoveConstructorMsg[];
ABSL_CONST_INIT extern const char kStatusMoveAssignmentMsg[];
#else
ABSL_CONST_INIT extern const char kValueMoveConstructorMsg[];
ABSL_CONST_INIT extern const char kValueMoveAssignmentMsg[];
ABSL_CONST_INIT extern const char kValueOrDieMovedMsg[];
ABSL_CONST_INIT extern const char kStatusMoveConstructorMsg[];
ABSL_CONST_INIT extern const char kStatusMoveAssignmentMsg[];
#endif

/// A class for representing either a usable value, or an error.
///
/// A StatusOr object either contains a value of type `T` or a Status object
/// explaining why such a value is not present. The type `T` must be
/// copy-constructible and/or move-constructible.
///
/// The state of a StatusOr object may be determined by calling ok() or
/// status(). The ok() method returns true if the object contains a valid value.
/// The status() method returns the internal Status object. A StatusOr object
/// that contains a valid value will return an OK Status for a call to status().
///
/// A value of type `T` may be extracted by dereferencing an OK StatusOr object,
/// either with operator*() or operator->(). These operators should only be
/// called if a call to ok() returns true. Sample usage:
///
/// ```
///   asylo::StatusOr<Foo> result = CalculateFoo();
///   if (result.ok()) {
///     Foo foo = *result;
///     foo.DoSomethingCool();
///   } else {
///     LOG(ERROR) << result.status();
///  }
/// ```
///
/// Or more concisely:
///
/// ```
///   asylo::StatusOr<Foo> result = CalculateFoo();
///   if (result.ok()) {
///     result->DoSomethingCool();
///   } else {
///     LOG(ERROR) << result.status();
///  }
/// ```
///
/// If `T` is a move-only type, like `std::unique_ptr<>`, then the value should
/// only be extracted after invoking `std::move()` on the StatusOr object.
/// Sample usage:
///
/// ```
///   asylo::StatusOr<std::unique_ptr<Foo>> result = CalculateFoo();
///   if (result.ok()) {
///     std::unique_ptr<Foo> foo = *std::move(result);
///     foo->DoSomethingCool();
///   } else {
///     LOG(ERROR) << result.status();
///   }
/// ```
///
/// If exceptions are enabled, callers can alternatively use the `value()`
/// method to extract the contents of a StatusOr. Calls to `value()` throw
/// `absl::BadStatusOrAccess` if the StatusOr is not OK. Sample usage:
///
/// ```
///   asylo::StatusOr<Foo> result = CalculateFoo();
///   try {
///     result.value().DoSomethingCool();
///   } catch (const absl::BadStatusOrAccess &bad_access) {
///     LOG(ERROR) << bad_access.status();
///  }
/// ```
///
/// If exceptions are disabled, then calls to `value()` on a non-OK StatusOr
/// will abort the program.
///
/// StatusOr is provided for the convenience of implementing functions that
/// return some value but may fail during execution. For instance, consider a
/// function with the following signature:
///
/// ```
///   asylo::Status CalculateFoo(int *output);
/// ```
///
/// This function may instead be written as:
///
/// ```
///   asylo::StatusOr<int> CalculateFoo();
/// ```
template <class T>
class StatusOr {
  template <typename U>
  friend class StatusOr;

  // A traits class that determines whether a type U is implicitly convertible
  // from a type V. If it is convertible, then the `value` member of this class
  // is statically set to true, otherwise it is statically set to false.
  template <class U, typename V>
  struct is_implicitly_constructible
      : absl::conjunction<std::is_constructible<U, V>,
                          std::is_convertible<V, U> > {};

 public:
  /// An alias for T. Useful for generic programming.
  using value_type = T;

  /// Constructs a StatusOr object that contains a non-OK status.
  /// The non-OK status has an error code of -1. This is a non-standard POSIX
  /// error code and is used in this context to indicate an unknown error.
  ///
  /// This constructor is marked `explicit` to prevent attempts to `return {}`
  /// from a function with a return type of, for example,
  /// `StatusOr<std::vector<int>>`. While `return {}` seems like it would return
  /// an empty vector, it will actually invoke the default constructor of
  /// StatusOr.
  explicit StatusOr()
      : variant_(Status(error::GoogleError::UNKNOWN, "Unknown error")),
        has_value_(false) {}

  ~StatusOr() {
    if (has_value_) {
      variant_.value_.~T();
    } else {
      variant_.status_.~Status();
    }
  }

  /// Constructs a StatusOr object with the given non-OK Status object. The
  /// given `status` must not be an OK status, otherwise this constructor will
  /// abort.
  ///
  /// This constructor is not declared explicit so that a function with a return
  /// type of `StatusOr<T>` can return a Status object, and the status will be
  /// implicitly converted to the appropriate return type as a matter of
  /// convenience.
  ///
  /// \param status The non-OK Status object to initalize to.
  StatusOr(const Status &status)
      : variant_(status), has_value_(false) {
    if (status.ok()) {
      LOG(FATAL) << "Cannot instantiate StatusOr with absl::OkStatus()";
    }
  }

  /// Constructs a StatusOr object with the given non-OK `absl::Status` object.
  /// All calls to value() on this object will throw an exception or cause the
  /// program to abort. The given `status` must not be an OK status, otherwise
  /// this constructor will cause an abort.
  ///
  /// This constructor is not declared explicit so that a function with a return
  /// type of `StatusOr<T>` can return an `absl::Status` object, and the status
  /// will be implicitly converted to the appropriate return type as a matter of
  /// convenience.
  ///
  /// \param status The non-OK `absl::Status` object to initalize to.
  StatusOr(const absl::Status &status)
      : variant_(Status(status)), has_value_(false) {
    if (status.ok()) {
      LOG(FATAL) << "Cannot instantiate StatusOr with absl::OkStatus()";
    }
  }

  /// Constructs a StatusOr object that contains `value`. The resulting object
  /// is considered to have an OK status. The wrapped element can be accessed
  /// by dereferencing or with value().
  ///
  /// This constructor is made implicit so that a function with a return type of
  /// `StatusOr<T>` can return an object of type `U &&`, implicitly converting
  /// it to a `StatusOr<T>` object.
  ///
  /// Note that `T` must be implicitly constructible from `U`, and `U` must not
  /// be a (cv-qualified) Status or Status-reference type. Due to C++
  /// reference-collapsing rules and perfect-forwarding semantics, this
  /// constructor matches invocations that pass `value` either as a const
  /// reference or as an rvalue reference. Since StatusOr needs to work for both
  /// reference and rvalue-reference types, the constructor uses perfect
  /// forwarding to avoid invalidating arguments that were passed by reference.
  /// See http://thbecker.net/articles/rvalue_references/section_08.html for
  /// additional details.
  ///
  /// \param value The value to initialize to.
  template <typename U,
            typename E = typename std::enable_if<
                is_implicitly_constructible<T, U>::value &&
                !std::is_same<typename std::remove_reference<
                                  typename std::remove_cv<U>::type>::type,
                              Status>::value &&
                !std::is_same<typename std::remove_reference<
                                  typename std::remove_cv<U>::type>::type,
                              absl::Status>::value>::type>
  StatusOr(U &&value) : variant_(std::forward<U>(value)), has_value_(true) {}

  /// Copy constructor.
  ///
  /// This constructor needs to be explicitly defined because the presence of
  /// the move-assignment operator deletes the default copy constructor. In such
  /// a scenario, since the deleted copy constructor has stricter binding rules
  /// than the templated copy constructor, the templated constructor cannot act
  /// as a copy constructor, and any attempt to copy-construct a `StatusOr`
  /// object results in a compilation error.
  ///
  /// \param other The value to copy from.
  StatusOr(const StatusOr &other) : has_value_(other.has_value_) {
    if (has_value_) {
      new (&variant_) variant(other.variant_.value_);
    } else {
      new (&variant_) variant(other.variant_.status_);
    }
  }

  /// Templatized constructor that constructs a `StatusOr<T>` from a const
  /// reference to a `StatusOr<U>`.
  ///
  /// `T` must be implicitly constructible from `const U &`.
  ///
  /// \param other The value to copy from.
  template <typename U,
            typename E = typename std::enable_if<
                is_implicitly_constructible<T, const U &>::value>::type>
  StatusOr(const StatusOr<U> &other)
      : has_value_(other.has_value_) {
    if (has_value_) {
      new (&variant_) variant(other.variant_.value_);
    } else {
      new (&variant_) variant(other.variant_.status_);
    }
  }

  /// Templatized constructor that constructs a `StatusOr<T>` from a const
  /// reference to an `absl::StatusOr<U>`.
  ///
  /// `T` must be implicitly constructible from `const U &`.
  ///
  /// \param other The value to copy from.
  template <typename U,
            typename E = typename std::enable_if<
                is_implicitly_constructible<T, const U &>::value>::type>
  StatusOr(const absl::StatusOr<U> &other)
      : has_value_(other.ok()) {
    if (has_value_) {
      new (&variant_) variant(*other);
    } else {
      new (&variant_) variant(other.status());
    }
  }

  /// Copy-assignment operator.
  ///
  /// \param other The StatusOr object to copy.
  StatusOr &operator=(const StatusOr &other) {
    // Check for self-assignment.
    if (this == &other) {
      return *this;
    }

    // Construct the variant object using the variant object of the source.
    if (other.has_value_) {
      AssignValue(other.variant_.value_);
    } else {
      AssignStatus(other.variant_.status_);
    }
    return *this;
  }

  /// Templatized constructor which constructs a `StatusOr<T>` by moving the
  /// contents of a `StatusOr<U>`. `T` must be implicitly constructible from `U
  /// &&`.
  ///
  /// Sets `other` to a valid but unspecified state.
  ///
  /// \param other The StatusOr object to move from.
  template <typename U, typename E = typename std::enable_if<
                            is_implicitly_constructible<T, U &&>::value>::type>
  StatusOr(StatusOr<U> &&other) : has_value_(other.has_value_) {
    if (has_value_) {
      new (&variant_) variant(std::move(other.variant_.value_));
      other.OverwriteValueWithStatus(
          Status(error::StatusError::MOVED, kValueMoveConstructorMsg));
    } else {
      new (&variant_) variant(std::move(other.variant_.status_));
#ifndef NDEBUG
      // The other.variant_.status_ gets moved and invalidated with a Status-
      // specific error message above. To aid debugging, set the status to a
      // StatusOr-specific error message.
      other.variant_.status_ =
          Status(error::StatusError::MOVED, kStatusMoveConstructorMsg);
#endif
    }
  }

  /// Templatized constructor which constructs a `StatusOr<T>` by moving the
  /// contents of an `absl::StatusOr<U>`. `T` must be implicitly constructible
  /// from `U &&`.
  ///
  /// \param other The `absl::StatusOr<U>` object to move from.
  template <typename U, typename E = typename std::enable_if<
                            is_implicitly_constructible<T, U &&>::value>::type>
  StatusOr(absl::StatusOr<U> &&other) : has_value_(other.ok()) {
    if (has_value_) {
      new (&variant_) variant(*std::move(other));
    } else {
      new (&variant_) variant(std::move(other).status());
    }
  }

  /// Move-assignment operator.
  ///
  /// Sets `other` to a valid but unspecified state.
  ///
  /// \param other The StatusOr object to assign from.
  StatusOr &operator=(StatusOr &&other) {
    // Check for self-assignment.
    if (this == &other) {
      return *this;
    }

    // Construct the variant object using the variant object of the donor.
    if (other.has_value_) {
      AssignValue(std::move(other.variant_.value_));
      other.OverwriteValueWithStatus(
          Status(error::StatusError::MOVED, kValueMoveAssignmentMsg));
    } else {
      AssignStatus(std::move(other.variant_.status_));
#ifndef NDEBUG
      // The other.variant_.status_ gets moved and invalidated with a Status-
      // specific error message above. To aid debugging, set the status to a
      // StatusOr-specific error message.
      other.variant_.status_ =
          Status(error::StatusError::MOVED, kStatusMoveAssignmentMsg);
#endif
    }

    return *this;
  }

  // Implicit conversion operator to absl::StatusOr<U> for any type U that is
  // implicitly constructible from T &&. This operator is provided for
  // interoperability with Abseil status types.
  template <typename U, typename E = typename std::enable_if<
                            is_implicitly_constructible<U, T &&>::value>::type>
  operator absl::StatusOr<U>() const {
    if (has_value_) {
      return variant_.value_;
    } else {
      return variant_.status_;
    }
  }

  /// Indicates whether the object contains a `T` value.
  ///
  /// \return True if this StatusOr object's status is OK (i.e. a call to ok()
  /// returns true). If this function returns true, then it is safe to
  /// dereference this StatusOr.
  bool ok() const { return has_value_; }

  /// Gets the stored status object, or an OK status if a `T` value is stored.
  ///
  /// \return The stored non-OK status object, or an OK status if this object
  ///         has a value.
  Status status() const { return ok() ? OkStatus() : variant_.status_; }

  /// Gets the stored `T` value.
  ///
  /// If this StatusOr object is not OK, then this method either throws an
  /// `absl::BadStatusOrAccess` exception or aborts the program, depending on
  /// whether exceptions are enabled.
  ///
  /// \return The stored `T` value.
  const T &value() const & {
    if (!ok()) {
      HandleBadValueCall();
    }
    return variant_.value_;
  }

  /// Gets the stored `T` value.
  ///
  /// If this StatusOr object is not OK, then this method either throws an
  /// `absl::BadStatusOrAccess` exception or aborts the program, depending on
  /// whether exceptions are enabled.
  ///
  /// \return The stored `T` value.
  T &value() & {
    if (!ok()) {
      HandleBadValueCall();
    }
    return variant_.value_;
  }

  /// Moves and returns the internally-stored `T` value.
  ///
  /// The StatusOr object is invalidated after this call and will be updated to
  /// a valid but unspecified state.
  ///
  /// If this StatusOr object is not OK, then this method either throws an
  /// `absl::BadStatusOrAccess` exception or aborts the program, depending on
  /// whether exceptions are enabled.
  ///
  /// \return The stored `T` value.
  T value() && {
    if (!ok()) {
      HandleBadValueCall();
    }
    return std::move(*this).MoveValue();
  }

  /// Gets the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise this call will abort.
  ///
  /// \deprecated Deprecated as part of Asylo's `absl::Status` migration. Use
  ///             `value()`, `operator*()`, or `operator->()` instead.
  /// \return The stored `T` value.
  ABSL_DEPRECATED(
      "Deprecated as part of Asylo's absl::Status migration. Use value(), "
      "operator*(), or operator->() instead.")
  const T &ValueOrDie() const & { return **this; }

  /// Gets a mutable reference to the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise this call will abort.
  ///
  /// \deprecated Deprecated as part of Asylo's `absl::Status` migration. Use
  ///             `value()`, `operator*()`, or `operator->()` instead.
  /// \return The stored `T` value.
  ABSL_DEPRECATED(
      "Deprecated as part of Asylo's absl::Status migration. Use value(), "
      "operator*(), or operator->() instead.")
  T &ValueOrDie() & { return **this; }

  /// Moves and returns the internally-stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise this call will abort. The
  /// StatusOr object is changed after this call to a valid but unspecified
  /// state.
  ///
  /// \deprecated Deprecated as part of Asylo's `absl::Status` migration. Use
  ///             `value()`, `operator*()`, or `operator->()` instead.
  /// \return The stored `T` value.
  ABSL_DEPRECATED(
      "Deprecated as part of Asylo's absl::Status migration. Use value(), "
      "operator*(), or operator->() instead.")
  T ValueOrDie() && { return *std::move(*this); }

  /// Gets the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise the behavior of this method
  /// is undefined.
  ///
  /// \return The stored `T` value.
  const T &operator*() const & {
    if (!ok()) {
      DieOnBadAccess();
    }
    return variant_.value_;
  }

  /// Gets the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise the behavior of this method
  /// is undefined.
  ///
  /// \return The stored `T` value.
  T &operator*() & {
    if (!ok()) {
      DieOnBadAccess();
    }
    return variant_.value_;
  }

  /// Gets the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise the behavior of this method
  /// is undefined. The StatusOr object is changed after this call to a valid
  /// but unspecified state.
  ///
  /// \return The stored `T` value.
  T operator*() && {
    if (!ok()) {
      DieOnBadAccess();
    }
    return std::move(*this).MoveValue();
  }

  /// Aecceses the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise the behavior of this method
  /// is undefined.
  ///
  /// \return A pointer to the stored `T` value.
  const T *operator->() const {
    if (!ok()) {
      DieOnBadAccess();
    }
    return &variant_.value_;
  }

  /// Gets the stored `T` value.
  ///
  /// This method should only be called if this StatusOr object's status is OK
  /// (i.e. a call to ok() returns true), otherwise the behavior of this method
  /// is undefined.
  ///
  /// \return The stored `T` value.
  T *operator->() {
    if (!ok()) {
      DieOnBadAccess();
    }
    return &variant_.value_;
  }

 private:
  // Resets the |variant_| member to contain |status|.
  template <class U>
  void AssignStatus(U &&status) {
    if (ok()) {
      OverwriteValueWithStatus(std::forward<U>(status));
    } else {
      // Reuse the existing Status object. has_value_ is already false.
      variant_.status_ = std::forward<U>(status);
    }
  }

  // Under the assumption that |this| is currently holding a value, resets the
  // |variant_| member to contain |status| and sets |has_value_| to indicate
  // that |this| does not have a value. Destroys the existing |variant_| member.
  template <class U>
  void OverwriteValueWithStatus(U &&status) {
#ifndef NDEBUG
    if (!ok()) {
      LOG(FATAL) << "Object does not have a value to change from";
    }
#endif
    variant_.value_.~T();
    new (&variant_) variant(std::forward<U>(status));
    has_value_ = false;
  }

  // Resets the |variant_| member to contain the |value| and sets |has_value_|
  // to indicate that the StatusOr object has a value. Destroys the existing
  // |variant_| member.
  template <class U>
  void AssignValue(U &&value) {
    if (ok()) {
      // We cannot assume that T is move-assignable.
      variant_.value_.~T();
    } else {
      variant_.status_.~Status();
    }
    new (&variant_) variant(std::forward<U>(value));
    has_value_ = true;
  }

  // If exceptions are enabled, throw an absl::BadStatusOrAccess. Otherwise,
  // crash the program.
  //
  // Requires this object to hold a Status.
  void HandleBadValueCall() const {
#ifdef ABSL_HAVE_EXCEPTIONS
    throw absl::BadStatusOrAccess(status());
#else
    DieOnBadAccess();
#endif
  }

  // If exceptions are enabled, throw an absl::BadStatusOrAccess. Otherwise,
  // crash the program.
  //
  // Requires this object to hold a Status.
  void DieOnBadAccess() const {
    LOG(FATAL)
        << "Object does not have a usable value, instead contains status: "
        << status();
  }

  // Moves the value out from this object. Requires this object to hold a value.
  T MoveValue() && {
    // Invalidate this StatusOr object before returning control to caller.
    Cleanup set_moved_status([this] {
      OverwriteValueWithStatus(
          Status(error::StatusError::MOVED, kValueOrDieMovedMsg));
    });
    return std::move(variant_.value_);
  }

  union variant {
    // A non-OK status.
    Status status_;

    // An element of type T.
    T value_;

    variant() {}

    variant(const Status &status) : status_(status) {}

    variant(Status &&status) : status_(std::move(status)) {}

    template <typename U, typename E = typename std::enable_if<
                              is_implicitly_constructible<T, U>::value>::type>
    variant(U &&value) : value_(std::forward<U>(value)) {}

    // This destructor must be explicitly defined because it is deleted due to
    // the variant type having non-static data members with non-trivial
    // destructors.
    ~variant() {}
  };

  // One of: a non-OK status or an element of type T.
  variant variant_;

  // Indicates the active member of the variant_ member.
  //
  // A value of true indicates that value_ is the active member of variant_.
  //
  // A value of false indicates that status_ is the active member of variant_.
  bool has_value_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_STATUSOR_H_
