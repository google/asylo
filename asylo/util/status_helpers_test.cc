/*
 * Copyright 2021 Asylo authors
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
 */

#include "asylo/util/status_helpers.h"

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <google/protobuf/stubs/status.h>
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/sgx_errors.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "include/grpcpp/support/status.h"
#include "include/sgx_error.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::MatchesRegex;
using ::testing::Optional;
using ::testing::Test;
using ::testing::Types;

// The canonical code and error message that all test statuses used in
// ConvertStatus() tests must have.
constexpr error::GoogleError kCanonicalCode =
    error::GoogleError::RESOURCE_EXHAUSTED;
constexpr absl::string_view kErrorMessage = "test error message";

// Provides test data and method access for different status types for
// ConvertStatus() tests. Each implementation must have the following memebers:
//
//     // Returns the error code of |status| in the canonical error space.
//     static int GetCanonicalCode(const StatusT &status) { ... }
//
//     // Returns the error message of |status|.
//     static std::string GetErrorMessage(const StatusT &status) { ... }
//
//     // Returns a vector of statuses that have canonical code and error
//     // message equal to kCanonicalCode and kErrorMessage, respectively.
//     static std::vector<StatusT> TestData() { ... }
template <typename StatusT>
struct StatusInfo;

template <>
struct StatusInfo<Status> {
  static int GetCanonicalCode(const Status &status) {
    return static_cast<int>(status.code());
  }

  static std::string GetErrorMessage(const Status &status) {
    return std::string(status.message());
  }

  static std::vector<Status> TestData() {
    return {Status(kCanonicalCode, kErrorMessage),
            SgxError(SGX_ERROR_OUT_OF_MEMORY, kErrorMessage)};
  }
};

template <>
struct StatusInfo<absl::Status> {
  static int GetCanonicalCode(const absl::Status &status) {
    return static_cast<int>(status.code());
  }

  static std::string GetErrorMessage(const absl::Status &status) {
    return std::string(status.message());
  }

  static std::vector<absl::Status> TestData() {
    return {absl::ResourceExhaustedError(kErrorMessage)};
  }
};

template <>
struct StatusInfo<grpc::Status> {
  static int GetCanonicalCode(const grpc::Status &status) {
    return static_cast<int>(status.error_code());
  }

  static std::string GetErrorMessage(const grpc::Status &status) {
    return status.error_message();
  }

  static std::vector<grpc::Status> TestData() {
    return {grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                         std::string(kErrorMessage))};
  }
};

template <>
struct StatusInfo<google::protobuf::util::Status> {
  static int GetCanonicalCode(const google::protobuf::util::Status &status) {
    return status.error_code();
  }

  static std::string GetErrorMessage(
      const google::protobuf::util::Status &status) {
    return std::string(status.error_message());
  }

  static std::vector<google::protobuf::util::Status> TestData() {
    return {google::protobuf::util::Status(
                google::protobuf::util::error::RESOURCE_EXHAUSTED,
                std::string(kErrorMessage))};
  }
};

// A test fixture for ConvertStatus() tests. StatusPairT must be of the form
// std::pair<ToStatusType, FromStatusType>.
template <typename StatusPairT>
class ConvertStatusTest : public Test {};

// Converts a std::tuple<Ts...> to a Types<Ts...>.
template <typename TupleT>
struct TupleToTypes;

template <typename... Ts>
struct TupleToTypes<std::tuple<Ts...>> {
  using Types_ = Types<Ts...>;
};

// Concatenates any number of lists of types represented as std::tuple<...>
// types.
template <typename... TupleTs>
using TupleCat = decltype(std::tuple_cat(std::declval<TupleTs>()...));

// Provides an alias for a std::tuple<...> of std::pair<T, U>s for each U in Us.
template <typename T, typename... Us>
struct TypeSquareRow {
  using Row = std::tuple<std::pair<T, Us>...>;
};

// Provides an alias for a std::tuple<...> of a std::pair<T, U> for each
// (ordered) pair of types T, U in Ts.
template <typename... Ts>
struct TypeSquare {
  using Square = TupleCat<typename TypeSquareRow<Ts, Ts...>::Row...>;
};

using StatusTypesSquare = TupleToTypes<
    TypeSquare<Status, absl::Status, grpc::Status,
               google::protobuf::util::Status>::Square>::Types_;
TYPED_TEST_SUITE(ConvertStatusTest, StatusTypesSquare);

TYPED_TEST(ConvertStatusTest, HasCorrectPropertiesAfterConversion) {
  using ToStatus = typename TypeParam::first_type;
  using FromStatus = typename TypeParam::second_type;
  using ToInfo = StatusInfo<ToStatus>;
  using FromInfo = StatusInfo<FromStatus>;

  for (const auto &from_status : FromInfo::TestData()) {
    ToStatus to_status = ConvertStatus<ToStatus>(from_status);
    EXPECT_THAT(ToInfo::GetCanonicalCode(to_status), Eq(kCanonicalCode));
    // Use HasSubstr() instead of Eq() because Status::ToCanonical() adds error
    // space information to the error message.
    EXPECT_THAT(ToInfo::GetErrorMessage(to_status), HasSubstr(kErrorMessage));
  }
}

TEST(StatusHelpersTest, GetTypeUrlReturnsExpectedUrl) {
  EXPECT_THAT(GetTypeUrl<EnclaveInput>(),
              Eq("type.googleapis.com/asylo.EnclaveInput"));
  EXPECT_THAT(GetTypeUrl<google::protobuf::Timestamp>(),
              Eq("type.googleapis.com/google.protobuf.Timestamp"));
}

// Provides traits for absl::Status-like types. Each specialization must have
// the following members:
//
//     // The Status type.
//     using StatusType = ...;
//
//     // The associated StatusOr type.
//     template <typename T>
//     using StatusOrType = ...;
template <typename StatusT>
struct AbslStatusLikeInfo;

template <>
struct AbslStatusLikeInfo<Status> {
  using StatusType = Status;

  template <typename T>
  using StatusOrType = StatusOr<T>;
};

template <>
struct AbslStatusLikeInfo<absl::Status> {
  using StatusType = absl::Status;

  template <typename T>
  using StatusOrType = absl::StatusOr<T>;
};

template <typename StatusT>
class AbslStatusLikeTest : public Test {};
using AbslStatusLikeTypes = Types<Status, absl::Status>;
TYPED_TEST_SUITE(AbslStatusLikeTest, AbslStatusLikeTypes);

TYPED_TEST(AbslStatusLikeTest, GetReturnsNulloptIfNoMatchingPayload) {
  typename AbslStatusLikeInfo<TypeParam>::StatusType status =
      absl::DeadlineExceededError("foobar");
  EXPECT_THAT(GetProtoPayload<google::protobuf::Struct>(status),
              Eq(absl::nullopt));
}

TYPED_TEST(AbslStatusLikeTest, GetReturnsNulloptIfPayloadFailsToParse) {
  typename AbslStatusLikeInfo<TypeParam>::StatusType status =
      absl::DeadlineExceededError("foobar");
  status.SetPayload(GetTypeUrl<google::protobuf::Struct>(),
                    absl::Cord("notaproto"));
  EXPECT_THAT(GetProtoPayload<google::protobuf::Struct>(status),
              Eq(absl::nullopt));
}

TYPED_TEST(AbslStatusLikeTest, GetReturnsPayloadAddedBySet) {
  google::protobuf::Struct proto;
  google::protobuf::Value value;
  value.set_string_value("bar");
  proto.mutable_fields()->insert({"foo", value});

  typename AbslStatusLikeInfo<TypeParam>::StatusType status =
      absl::DeadlineExceededError("foobar");
  SetProtoPayload(proto, status);
  EXPECT_THAT(GetProtoPayload<google::protobuf::Struct>(status),
              Optional(EqualsProto(proto)));
}

TYPED_TEST(AbslStatusLikeTest, WithContextDoesNothingToOkStatus) {
  typename AbslStatusLikeInfo<TypeParam>::StatusType status = absl::OkStatus();
  EXPECT_THAT(WithContext(status, "some context"), Eq(absl::OkStatus()));
}

TYPED_TEST(AbslStatusLikeTest, WithContextAddsContextToNonOkStatus) {
  typename AbslStatusLikeInfo<TypeParam>::StatusType status =
      absl::DeadlineExceededError("foobar");
  EXPECT_THAT(WithContext(status, "some context"),
              StatusIs(absl::StatusCode::kDeadlineExceeded,
                       MatchesRegex(".*some context.*foobar.*")));
}

TYPED_TEST(AbslStatusLikeTest, WithContextDoesNothingToOkStatusOr) {
  typename AbslStatusLikeInfo<TypeParam>::template StatusOrType<int> status_or(
      5);
  EXPECT_THAT(WithContext(status_or, "some context"), IsOkAndHolds(Eq(5)));
}

TYPED_TEST(AbslStatusLikeTest, WithContextAddsContextToNonOkStatusOr) {
  typename AbslStatusLikeInfo<TypeParam>::template StatusOrType<int> status_or(
      absl::DeadlineExceededError("foobar"));
  EXPECT_THAT(WithContext(status_or, "some context"),
              StatusIs(absl::StatusCode::kDeadlineExceeded,
                       MatchesRegex(".*some context.*foobar.*")));
}

}  // namespace
}  // namespace asylo
