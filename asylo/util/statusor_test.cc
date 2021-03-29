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

#include "asylo/util/statusor.h"

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/config.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_error_space.h"

namespace asylo {
namespace {

using ::testing::Not;

absl::StatusCode kErrorCode = absl::StatusCode::kInvalidArgument;
constexpr char kErrorMessage[] = "Invalid argument";

const int kIntElement = 42;
constexpr char kStringElement[] =
    "The Answer to the Ultimate Question of Life, the Universe, and Everything";

// A data type without a default constructor.
struct Foo {
  int bar;
  std::string baz;

  Foo() = delete;
  explicit Foo(int value) : bar(value), baz(kStringElement) {}
};

// A data type with only copy constructors.
struct CopyOnlyDataType {
  explicit CopyOnlyDataType(int x) : data(x) {}

  CopyOnlyDataType(const CopyOnlyDataType &other) = default;
  CopyOnlyDataType &operator=(const CopyOnlyDataType &other) = default;

  int data;
};

struct ImplicitlyCopyConvertible {
  ImplicitlyCopyConvertible(const CopyOnlyDataType &co) : copy_only(co) {}

  CopyOnlyDataType copy_only;
};

// A data type with only move constructors.
struct MoveOnlyDataType {
  explicit MoveOnlyDataType(int x) : data(new int(x)) {}

  MoveOnlyDataType(MoveOnlyDataType &&other) : data(other.data) {
    other.data = nullptr;
  }

  MoveOnlyDataType &operator=(MoveOnlyDataType &&other) {
    if (&other == this) {
      return *this;
    }
    if (data) {
      delete data;
    }
    data = other.data;
    other.data = nullptr;
    return *this;
  }

  MoveOnlyDataType(const MoveOnlyDataType &other) = delete;
  MoveOnlyDataType &operator=(const MoveOnlyDataType &other) = delete;

  ~MoveOnlyDataType() {
    delete data;
    data = nullptr;
  }

  int *data;
};

struct ImplicitlyMoveConvertible {
  ImplicitlyMoveConvertible(MoveOnlyDataType &&mo) : move_only(std::move(mo)) {}

  MoveOnlyDataType move_only;
};

// A data type with dynamically-allocated data.
struct HeapAllocatedObject {
  int *value;

  HeapAllocatedObject() {
    value = new int;
    *value = kIntElement;
  }

  HeapAllocatedObject(const HeapAllocatedObject &other) {
    value = new int;
    *value = *other.value;
  }

  HeapAllocatedObject(HeapAllocatedObject &&other) {
    value = other.value;
    other.value = nullptr;
  }

  ~HeapAllocatedObject() { delete value; }
};

// Constructs a Foo.
struct FooCtor {
  using value_type = Foo;

  Foo operator()() { return Foo(kIntElement); }
};

// Constructs a HeapAllocatedObject.
struct HeapAllocatedObjectCtor {
  using value_type = HeapAllocatedObject;

  HeapAllocatedObject operator()() { return HeapAllocatedObject(); }
};

// Constructs an integer.
struct IntCtor {
  using value_type = int;

  int operator()() { return kIntElement; }
};

// Constructs a string.
struct StringCtor {
  using value_type = std::string;

  std::string operator()() { return std::string(kStringElement); }
};

// Constructs a vector of strings.
struct StringVectorCtor {
  using value_type = std::vector<std::string>;

  std::vector<std::string> operator()() {
    return {kStringElement, kErrorMessage};
  }
};

bool operator==(const Foo &lhs, const Foo &rhs) {
  return (lhs.bar == rhs.bar) && (lhs.baz == rhs.baz);
}

bool operator==(const HeapAllocatedObject &lhs,
                const HeapAllocatedObject &rhs) {
  return *lhs.value == *rhs.value;
}

// Returns an rvalue reference to the StatusOr<T> object pointed to by
// |statusor|.
template <class T>
StatusOr<T> &&MoveStatusOr(StatusOr<T> *statusor) {
  return std::move(*statusor);
}

// Forwards a StatusOr<T>.
template <typename T>
StatusOr<T> ForwardStatusOr(StatusOr<T> statusor) {
  return statusor;
}

// Forwards an absl::StatusOr<T>.
template <typename T>
absl::StatusOr<T> ForwardAbslStatusOr(absl::StatusOr<T> absl_statusor) {
  return absl_statusor;
}

// A test fixture is required for typed tests.
template <typename T>
class StatusOrTest : public ::testing::Test {};

typedef ::testing::Types<IntCtor, FooCtor, StringCtor, StringVectorCtor,
                         HeapAllocatedObjectCtor>
    TestTypes;

TYPED_TEST_SUITE(StatusOrTest, TestTypes);

// Verify that the default constructor for StatusOr constructs an object with a
// non-ok status.
TYPED_TEST(StatusOrTest, ConstructorDefault) {
  StatusOr<typename TypeParam::value_type> statusor;
  EXPECT_FALSE(statusor.ok());
  EXPECT_EQ(statusor.status().raw_code(),
            static_cast<int>(absl::StatusCode::kUnknown));
}

// Verify that StatusOr can be constructed from a Status object.
TYPED_TEST(StatusOrTest, ConstructorStatus) {
  StatusOr<typename TypeParam::value_type> statusor(
      Status(kErrorCode, kErrorMessage));

  EXPECT_FALSE(statusor.ok());
  EXPECT_FALSE(statusor.status().ok());
  EXPECT_EQ(statusor.status(), Status(kErrorCode, kErrorMessage));
}

// Verify that StatusOr can be constructed from an object of its element type.
TYPED_TEST(StatusOrTest, ConstructorElementConstReference) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> statusor(value);

  ASSERT_THAT(statusor, IsOk());
  ASSERT_THAT(statusor.status(), IsOk());
  EXPECT_EQ(*statusor, value);
}

// Verify that StatusOr can be constructed from an rvalue reference of an object
// of its element type.
TYPED_TEST(StatusOrTest, ConstructorElementRValue) {
  typename TypeParam::value_type value = TypeParam()();
  typename TypeParam::value_type value_copy(value);
  StatusOr<typename TypeParam::value_type> statusor(std::move(value));

  ASSERT_THAT(statusor, IsOk());
  ASSERT_THAT(statusor.status(), IsOk());

  // Compare to a copy of the original value, since the original was moved.
  EXPECT_EQ(*statusor, value_copy);
}

// Verify that StatusOr can be copy-constructed from a StatusOr with a non-ok
// status.
TYPED_TEST(StatusOrTest, CopyConstructorNonOkStatus) {
  StatusOr<typename TypeParam::value_type> statusor1 =
      Status(kErrorCode, kErrorMessage);
  StatusOr<typename TypeParam::value_type> statusor2(statusor1);

  EXPECT_EQ(statusor1.ok(), statusor2.ok());
  EXPECT_EQ(statusor1.status(), statusor2.status());
}

// Verify that StatusOr can be copy-constructed from a StatusOr with an ok
// status.
TYPED_TEST(StatusOrTest, CopyConstructorOkStatus) {
  StatusOr<typename TypeParam::value_type> statusor1((TypeParam()()));
  StatusOr<typename TypeParam::value_type> statusor2(statusor1);

  EXPECT_EQ(statusor1.ok(), statusor2.ok());
  ASSERT_THAT(statusor2, IsOk());
  EXPECT_EQ(*statusor1, *statusor2);
}

// Verify that copy-assignment of a StatusOr with a non-ok is working as
// expected.
TYPED_TEST(StatusOrTest, CopyAssignmentNonOkStatus) {
  StatusOr<typename TypeParam::value_type> statusor1(
      Status(kErrorCode, kErrorMessage));
  StatusOr<typename TypeParam::value_type> statusor2((TypeParam()()));

  // Invoke the copy-assignment operator.
  statusor2 = statusor1;
  EXPECT_EQ(statusor1.ok(), statusor2.ok());
  EXPECT_EQ(statusor1.status(), statusor2.status());
}

// Verify that copy-assignment of a StatusOr with an ok status is working as
// expected.
TYPED_TEST(StatusOrTest, CopyAssignmentOkStatus) {
  StatusOr<typename TypeParam::value_type> statusor1((TypeParam()()));
  StatusOr<typename TypeParam::value_type> statusor2(
      Status(kErrorCode, kErrorMessage));

  // Invoke the copy-assignment operator.
  statusor2 = statusor1;
  EXPECT_EQ(statusor1.ok(), statusor2.ok());
  ASSERT_THAT(statusor2, IsOk());
  EXPECT_EQ(*statusor1, *statusor2);
}

// Verify that copy-assignment of a StatusOr with a non-ok status to itself is
// properly handled.
TYPED_TEST(StatusOrTest, CopyAssignmentSelfNonOkStatus) {
  Status status(kErrorCode, kErrorMessage);
  StatusOr<typename TypeParam::value_type> statusor(status);
  statusor = *&statusor;

  EXPECT_FALSE(statusor.ok());
  EXPECT_EQ(statusor.status(), status);
}

// Verify that copy-assignment of a StatusOr with an ok status to itself is
// properly handled.
TYPED_TEST(StatusOrTest, CopyAssignmentSelfOkStatus) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> statusor(value);
  statusor = *&statusor;

  ASSERT_THAT(statusor, IsOk());
  EXPECT_EQ(*statusor, value);
}

// Verify that StatusOr can be move-constructed from a StatusOr with a non-ok
// status.
TYPED_TEST(StatusOrTest, MoveConstructorNonOkStatus) {
  Status status(kErrorCode, kErrorMessage);
  StatusOr<typename TypeParam::value_type> statusor1(status);
  StatusOr<typename TypeParam::value_type> statusor2(std::move(statusor1));

  // Verify that the status of the donor object was updated.
  EXPECT_FALSE(statusor1.ok());
  EXPECT_THAT(statusor1,
              StatusIs(error::StatusError::MOVED, kStatusMoveConstructorMsg));

  // Verify that the destination object contains the status previously held by
  // the donor.
  EXPECT_FALSE(statusor2.ok());
  EXPECT_EQ(statusor2.status(), status);
}

// Verify that StatusOr can be move-constructed from a StatusOr with an ok
// status.
TYPED_TEST(StatusOrTest, MoveConstructorOkStatus) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> statusor1(value);
  StatusOr<typename TypeParam::value_type> statusor2(std::move(statusor1));

  // Verify that the donor object was updated to contain a non-ok status.
  EXPECT_FALSE(statusor1.ok());
  EXPECT_THAT(statusor1,
              StatusIs(error::StatusError::MOVED, kValueMoveConstructorMsg));

  // The destination object should possess the value previously held by the
  // donor.
  ASSERT_THAT(statusor2, IsOk());
  EXPECT_EQ(*statusor2, value);
}

// Verify that move-assignment from a StatusOr with a non-ok status is working
// as expected.
TYPED_TEST(StatusOrTest, MoveAssignmentOperatorNonOkStatus) {
  Status status(kErrorCode, kErrorMessage);
  StatusOr<typename TypeParam::value_type> statusor1(status);
  StatusOr<typename TypeParam::value_type> statusor2((TypeParam()()));

  // Invoke the move-assignment operator.
  statusor2 = std::move(statusor1);

  // Verify that the status of the donor object was updated.
  EXPECT_FALSE(statusor1.ok());
  EXPECT_THAT(statusor1,
              StatusIs(error::StatusError::MOVED, kStatusMoveAssignmentMsg));

  // Verify that the destination object contains the status previously held by
  // the donor.
  EXPECT_FALSE(statusor2.ok());
  EXPECT_EQ(statusor2.status(), status);
}

// Verify that move-assignment from a StatusOr with an ok status is working as
// expected.
TYPED_TEST(StatusOrTest, MoveAssignmentOperatorOkStatus) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> statusor1(value);
  StatusOr<typename TypeParam::value_type> statusor2(
      Status(kErrorCode, kErrorMessage));

  // Invoke the move-assignment operator.
  statusor2 = std::move(statusor1);

  // Verify that the donor object was updated to contain a non-ok status.
  EXPECT_FALSE(statusor1.ok());
  EXPECT_THAT(statusor1,
              StatusIs(error::StatusError::MOVED, kValueMoveAssignmentMsg));

  // The destination object should possess the value previously held by the
  // donor.
  ASSERT_THAT(statusor2, IsOk());
  EXPECT_EQ(*statusor2, value);
}

// Verify that move-assignment of a StatusOr with a non-ok status to itself is
// handled properly.
TYPED_TEST(StatusOrTest, MoveAssignmentSelfNonOkStatus) {
  Status status(kErrorCode, kErrorMessage);
  StatusOr<typename TypeParam::value_type> statusor(status);

  statusor = MoveStatusOr(&statusor);

  EXPECT_FALSE(statusor.ok());
  EXPECT_EQ(statusor.status(), status);
}

// Verify that move-assignment of a StatusOr with an ok-status to itself is
// handled properly.
TYPED_TEST(StatusOrTest, MoveAssignmentSelfOkStatus) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> statusor(value);

  statusor = MoveStatusOr(&statusor);

  ASSERT_THAT(statusor, IsOk());
  EXPECT_EQ(*statusor, value);
}

TYPED_TEST(StatusOrTest, ImplicitConstructionFromAbslStatus) {
  absl::Status absl_status = absl::InvalidArgumentError("foobar");
  StatusOr<typename TypeParam::value_type> statusor =
      ForwardStatusOr<typename TypeParam::value_type>(absl_status);
  EXPECT_THAT(statusor, StatusIs(absl_status.code(), absl_status.message()));
}

TYPED_TEST(StatusOrTest, ImplicitConstructionFromAbslStatusOr) {
  typename TypeParam::value_type value = TypeParam()();
  absl::StatusOr<typename TypeParam::value_type> ok_statusor = value;
  EXPECT_THAT(ForwardStatusOr<typename TypeParam::value_type>(ok_statusor),
              IsOkAndHolds(value));

  absl::StatusOr<typename TypeParam::value_type> error_statusor =
      absl::InvalidArgumentError("foobar");
  EXPECT_THAT(ForwardStatusOr<typename TypeParam::value_type>(error_statusor),
              StatusIs(error_statusor.status().code(),
                       error_statusor.status().message()));
}

TYPED_TEST(StatusOrTest, ImplicitConversionToAbslStatusOr) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> ok_statusor = value;
  EXPECT_THAT(ForwardAbslStatusOr<typename TypeParam::value_type>(ok_statusor),
              IsOkAndHolds(value));

  StatusOr<typename TypeParam::value_type> error_statusor =
      absl::InvalidArgumentError("foobar");
  EXPECT_THAT(
      ForwardAbslStatusOr<typename TypeParam::value_type>(error_statusor),
      StatusIs(error_statusor.status().code(),
               error_statusor.status().message()));
}

#ifdef ABSL_HAVE_EXCEPTIONS
// Verify that using value() on a StatusOr with a non-OK status throws an
// exception on platforms where exceptions are enabled.
TYPED_TEST(StatusOrTest, ValueThrowsExceptionOnNonOkStatus) {
  Status status(kErrorCode, kErrorMessage);
  const StatusOr<typename TypeParam::value_type> const_statusor(status);
  StatusOr<typename TypeParam::value_type> statusor(const_statusor);

  ASSERT_THROW(const_statusor.value(), absl::BadStatusOrAccess);
  ASSERT_THROW(statusor.value(), absl::BadStatusOrAccess);
  ASSERT_THROW(std::move(statusor).value(), absl::BadStatusOrAccess);
}
#endif  // ABSL_HAVE_EXCEPTIONS

// Verify that the asylo::IsOk() gMock matcher works with StatusOr<T>.
TYPED_TEST(StatusOrTest, IsOkMatcher) {
  typename TypeParam::value_type value = TypeParam()();
  StatusOr<typename TypeParam::value_type> statusor(value);

  EXPECT_THAT(statusor, IsOk());

  statusor = StatusOr<typename TypeParam::value_type>(
      Status(kErrorCode, kErrorMessage));
  EXPECT_THAT(statusor, Not(IsOk()));
}

// Tests for move-only types. These tests use std::unique_ptr<> as the
// test type, since it is valuable to support this type in the Asylo infra.
// These tests are not part of the typed test suite for the following reasons:
//   * std::unique_ptr<> cannot be used as a type in tests that expect
//   the test type to support copy operations.
//   * std::unique_ptr<> provides an equality operator that checks equality of
//   the underlying ptr. Consequently, it is difficult to generalize existing
//   tests that verify value access functionality using equality comparisons.

// Verify that a StatusOr object can be constructed from a move-only type.
TEST(StatusOrTest, InitializationMoveOnlyType) {
  std::string *str = new std::string(kStringElement);
  std::unique_ptr<std::string> value(str);
  StatusOr<std::unique_ptr<std::string>> statusor(std::move(value));

  ASSERT_THAT(statusor, IsOk());
  EXPECT_EQ(statusor->get(), str);
}

// Verify that a StatusOr object can be move-constructed from a move-only type.
TEST(StatusOrTest, MoveConstructorMoveOnlyType) {
  std::string *str = new std::string(kStringElement);
  std::unique_ptr<std::string> value(str);
  StatusOr<std::unique_ptr<std::string>> statusor1(std::move(value));
  StatusOr<std::unique_ptr<std::string>> statusor2(std::move(statusor1));

  // Verify that the donor object was updated to contain a non-ok status.
  EXPECT_FALSE(statusor1.ok());
  EXPECT_THAT(statusor1, StatusIs(error::StatusError::MOVED,
                                  kValueMoveConstructorMsg));

  // The destination object should possess the value previously held by the
  // donor.
  ASSERT_THAT(statusor2, IsOk());
  EXPECT_EQ(statusor2->get(), str);
}

// Verify that a StatusOr object can be move-assigned to from a StatusOr object
// containing a move-only type.
TEST(StatusOrTest, MoveAssignmentMoveOnlyType) {
  std::string *str = new std::string(kStringElement);
  std::unique_ptr<std::string> value(str);
  StatusOr<std::unique_ptr<std::string>> statusor1(std::move(value));
  StatusOr<std::unique_ptr<std::string>> statusor2(
      Status(kErrorCode, kErrorMessage));

  // Invoke the move-assignment operator.
  statusor2 = std::move(statusor1);

  // Verify that the donor object was updated to contain a non-ok status.
  EXPECT_FALSE(statusor1.ok());
  EXPECT_THAT(statusor1,
              StatusIs(error::StatusError::MOVED, kValueMoveAssignmentMsg));

  // The destination object should possess the value previously held by the
  // donor.
  ASSERT_THAT(statusor2, IsOk());
  EXPECT_EQ(statusor2->get(), str);
}

// Verify that a value can be moved out of a StatusOr object.
TEST(StatusOrTest, AccessValueViaMove) {
  std::string *str = new std::string(kStringElement);
  std::unique_ptr<std::string> value(str);
  StatusOr<std::unique_ptr<std::string>> statusor(std::move(value));

  std::unique_ptr<std::string> moved_value = *std::move(statusor);
  EXPECT_EQ(moved_value.get(), str);
  EXPECT_EQ(*moved_value, kStringElement);

  // Verify that the StatusOr object was invalidated after the value was moved.
  EXPECT_FALSE(statusor.status().ok());
  EXPECT_THAT(statusor,
              StatusIs(error::StatusError::MOVED, kValueOrDieMovedMsg));
}

// Verify that a StatusOr<T> is implicitly constructible from some U, where T is
// a type which has an implicit constructor taking a const U &.
TEST(StatusOrTest, TemplateValueCopyConstruction) {
  CopyOnlyDataType copy_only(kIntElement);
  StatusOr<ImplicitlyCopyConvertible> statusor(copy_only);

  EXPECT_THAT(statusor, IsOk());
  EXPECT_EQ(statusor->copy_only.data, kIntElement);
}

// Verify that a StatusOr<T> is implicitly constructible from some U, where T is
// a type which has an implicit constructor taking a U &&.
TEST(StatusOrTest, TemplateValueMoveConstruction) {
  MoveOnlyDataType move_only(kIntElement);
  StatusOr<ImplicitlyMoveConvertible> statusor(std::move(move_only));

  EXPECT_THAT(statusor, IsOk());
  EXPECT_EQ(*statusor->move_only.data, kIntElement);
}

// Verify that a StatusOr<U> is assignable to a StatusOr<T>, where T
// is a type which has an implicit constructor taking a const U &.
TEST(StatusOrTest, TemplateCopyAssign) {
  CopyOnlyDataType copy_only(kIntElement);
  StatusOr<CopyOnlyDataType> statusor(copy_only);

  StatusOr<ImplicitlyCopyConvertible> statusor2 = statusor;

  EXPECT_THAT(statusor, IsOk());
  EXPECT_EQ(statusor->data, kIntElement);
  EXPECT_THAT(statusor2, IsOk());
  EXPECT_EQ(statusor2->copy_only.data, kIntElement);
}

// Verify that a StatusOr<U> is assignable to a StatusOr<T>, where T is a type
// which has an implicit constructor taking a U &&.
TEST(StatusOrTest, TemplateMoveAssign) {
  MoveOnlyDataType move_only(kIntElement);
  StatusOr<MoveOnlyDataType> statusor(std::move(move_only));

  StatusOr<ImplicitlyMoveConvertible> statusor2 = std::move(statusor);

  EXPECT_THAT(statusor2, IsOk());
  EXPECT_EQ(*statusor2->move_only.data, kIntElement);

  //  NOLINTNEXTLINE use after move.
  EXPECT_THAT(statusor, Not(IsOk()));
  //  NOLINTNEXTLINE use after move.
  EXPECT_THAT(statusor,
              StatusIs(error::StatusError::MOVED, kValueMoveConstructorMsg));
}

// Verify that a StatusOr<U> is constructible from a StatusOr<T>, where T is a
// type which has an implicit constructor taking a const U &.
TEST(StatusOrTest, TemplateCopyConstruct) {
  CopyOnlyDataType copy_only(kIntElement);
  StatusOr<CopyOnlyDataType> statusor(copy_only);
  StatusOr<ImplicitlyCopyConvertible> statusor2(statusor);

  EXPECT_THAT(statusor, IsOk());
  EXPECT_EQ(statusor->data, kIntElement);
  EXPECT_THAT(statusor2, IsOk());
  EXPECT_EQ(statusor2->copy_only.data, kIntElement);
}

// Verify that a StatusOr<U> is constructible from a StatusOr<T>, where T is a
// type which has an implicit constructor taking a U &&.
TEST(StatusOrTest, TemplateMoveConstruct) {
  MoveOnlyDataType move_only(kIntElement);
  StatusOr<MoveOnlyDataType> statusor(std::move(move_only));
  StatusOr<ImplicitlyMoveConvertible> statusor2(std::move(statusor));

  EXPECT_THAT(statusor2, IsOk());
  EXPECT_EQ(*statusor2->move_only.data, kIntElement);

  //  NOLINTNEXTLINE use after move.
  EXPECT_THAT(statusor, Not(IsOk()));
  //  NOLINTNEXTLINE use after move.
  EXPECT_THAT(statusor,
              StatusIs(error::StatusError::MOVED, kValueMoveConstructorMsg));
}

}  // namespace
}  // namespace asylo
