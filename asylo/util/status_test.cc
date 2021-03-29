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

#include "asylo/util/status.h"

#include <string>

#include <google/protobuf/stubs/status.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/posix_error_space.h"
#include "include/grpcpp/support/status.h"

// Suppress deprecation warnings on deprecated methods of Status that we test
// here. Many of those methods are currently used to implement their replacement
// APIs.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Optional;

constexpr char kErrorMessage1[] = "Bad foo argument";
constexpr char kErrorMessage2[] = "Internal foobar error";

constexpr char kBadErrorSpace[] = "Foo bar error space";

constexpr char kContext[] = "At index 1";
constexpr char kErrorMessage1WithPrependedContext[] =
    "At index 1: Bad foo argument";

constexpr char kTypeUrl[] = "test.URL";
constexpr char kPayload[] = "test payload";

TEST(StatusTest, OkSuccess) { EXPECT_TRUE(::asylo::OkStatus().ok()); }

TEST(StatusTest, OkFailure) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_FALSE(status.ok());
}

TEST(StatusTest, GetErrorCodeOkStatus) {
  EXPECT_EQ(::asylo::OkStatus().raw_code(),
            static_cast<int>(absl::StatusCode::kOk));
}

TEST(StatusTest, GetErrorCodeNonOkStatus) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_EQ(status.raw_code(),
            static_cast<int>(absl::StatusCode::kInvalidArgument));
}

TEST(StatusTest, GetErrorMessageOkStatus) {
  EXPECT_TRUE(OkStatus().message().empty());
}

TEST(StatusTest, GetErrorMessageNonOkStatus) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_EQ(status.message(), kErrorMessage1);
}

TEST(StatusTest, GetErrorSpaceOkStatus) {
  const error::ErrorSpace *error_space = OkStatus().error_space();
  EXPECT_EQ(error_space->SpaceName(), error::kCanonicalErrorSpaceName);
}

TEST(StatusTest, GetErrorSpaceNonOkStatus) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  const error::ErrorSpace *error_space = status.error_space();
  EXPECT_EQ(error_space->SpaceName(), error::kCanonicalErrorSpaceName);
}

TEST(StatusTest, ToStringOkStatus) {
  ::asylo::Status status = OkStatus();
  std::string error_code_name = status.error_space()->String(status.raw_code());

  // The ToString() representation for an ok Status should contain the error
  // code name.
  std::string status_rep = status.ToString();
  EXPECT_NE(status_rep.find(error_code_name), std::string::npos);
}

TEST(StatusTest, ToStringNonOkStatus) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  std::string error_code_name = status.error_space()->String(status.raw_code());
  std::string error_space_name = status.error_space()->SpaceName();
  // The format of ToString() is subject to change for a non-ok Status, but it
  // should contain the error space name, the error code name, and the error
  // message.
  std::string status_rep = status.ToString();
  EXPECT_NE(status_rep.find(error_space_name), std::string::npos);
  EXPECT_NE(status_rep.find(error_code_name), std::string::npos);
  EXPECT_NE(status_rep.find(std::string(status.message())), std::string::npos);
}

TEST(StatusTest, Equality) {
  ::asylo::Status ok_status = OkStatus();
  Status error_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  Status error_status_with_payload = error_status;
  error_status_with_payload.SetPayload(kTypeUrl, absl::Cord(kPayload));

  EXPECT_TRUE(ok_status == ok_status);
  EXPECT_TRUE(ok_status == absl::OkStatus());
  EXPECT_TRUE(absl::OkStatus() == ok_status);

  EXPECT_TRUE(error_status == error_status);
  EXPECT_TRUE(error_status_with_payload == error_status_with_payload);
  EXPECT_TRUE(error_status_with_payload ==
              absl::Status(error_status_with_payload));
  EXPECT_TRUE(absl::Status(error_status_with_payload) ==
              error_status_with_payload);

  EXPECT_FALSE(ok_status == error_status);
  EXPECT_FALSE(ok_status == absl::Status(error_status));
  EXPECT_FALSE(absl::OkStatus() == error_status);

  EXPECT_FALSE(error_status == error_status_with_payload);
  EXPECT_FALSE(error_status == absl::Status(error_status_with_payload));
  EXPECT_FALSE(absl::Status(error_status) == error_status_with_payload);

  EXPECT_FALSE(error_status_with_payload == ok_status);
  EXPECT_FALSE(error_status_with_payload == absl::OkStatus());
  EXPECT_FALSE(absl::Status(error_status_with_payload) == ok_status);
}

TEST(StatusTest, Inequality) {
  asylo::Status ok_status = OkStatus();
  asylo::Status invalid_arg_status(absl::StatusCode::kInvalidArgument,
                                   kErrorMessage1);
  asylo::Status internal_status(absl::StatusCode::kInternal, kErrorMessage2);
  asylo::Status internal_status_with_payload = internal_status;
  internal_status_with_payload.SetPayload(kTypeUrl, absl::Cord(kPayload));

  EXPECT_FALSE(ok_status != ok_status);
  EXPECT_FALSE(absl::OkStatus() != ok_status);
  EXPECT_FALSE(ok_status != absl::OkStatus());

  EXPECT_FALSE(invalid_arg_status != invalid_arg_status);
  EXPECT_FALSE(invalid_arg_status != absl::Status(invalid_arg_status));
  EXPECT_FALSE(absl::Status(invalid_arg_status) != invalid_arg_status);

  EXPECT_TRUE(ok_status != invalid_arg_status);
  EXPECT_TRUE(ok_status != absl::Status(invalid_arg_status));
  EXPECT_TRUE(absl::OkStatus() != invalid_arg_status);

  EXPECT_TRUE(invalid_arg_status != ok_status);
  EXPECT_TRUE(invalid_arg_status != absl::OkStatus());
  EXPECT_TRUE(absl::Status(invalid_arg_status) != ok_status);

  EXPECT_TRUE(invalid_arg_status != internal_status);
  EXPECT_TRUE(invalid_arg_status != absl::Status(internal_status));
  EXPECT_TRUE(absl::Status(invalid_arg_status) != internal_status);

  EXPECT_TRUE(internal_status != invalid_arg_status);
  EXPECT_TRUE(internal_status != absl::Status(invalid_arg_status));
  EXPECT_TRUE(absl::Status(internal_status) != invalid_arg_status);

  EXPECT_TRUE(internal_status != internal_status_with_payload);
  EXPECT_TRUE(internal_status != absl::Status(internal_status_with_payload));
  EXPECT_TRUE(absl::Status(internal_status) != internal_status_with_payload);
}

TEST(StatusTest, ToCanonicalOk) {
  EXPECT_EQ(OkStatus().ToCanonical(), OkStatus());
}

TEST(StatusTest, ToCanonicalNonOk) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_EQ(status.ToCanonical(), status);
}

TEST(StatusTest, ToCanonicalNonOkNonCanonical) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  Status canonical = status.ToCanonical();

  // Status objects outside the canonical error space are converted as follows:
  //   * Error code is converted to the equivalent code in the canonical error
  //   space
  //   * Error message is set to the ToString() representation
  EXPECT_EQ(canonical,
            Status(absl::StatusCode::kInvalidArgument, status.ToString()));
}

TEST(StatusTest, ToCanonicalNonOkWithPayload) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  Status canonical = status.ToCanonical();

  EXPECT_EQ(canonical, status);
}

TEST(StatusTest, ToCanonicalNonOkNonCanonicalWithPayload) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  Status canonical = status.ToCanonical();

  EXPECT_TRUE(canonical.Is(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.ToString(), HasSubstr(canonical.message()));
  EXPECT_THAT(canonical.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));
}

TEST(StatusTest, CodeAndCanonicalCodeOk) {
  EXPECT_EQ(OkStatus().code(), absl::StatusCode::kOk);
  EXPECT_EQ(OkStatus().CanonicalCode(), error::GoogleError::OK);
}

TEST(StatusTest, CodeAndCanonicalCodeNonOk) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_EQ(status.code(), static_cast<absl::StatusCode>(status.raw_code()));
}

TEST(StatusTest, CodeAndCanonicalCodeNonOkNonCanonical) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(status.CanonicalCode(), error::GoogleError::INVALID_ARGUMENT);
}

TEST(StatusTest, SaveTo) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  ::asylo::StatusProto status_proto;
  status.SaveTo(&status_proto);

  EXPECT_EQ(status_proto.code(), status.raw_code());
  EXPECT_EQ(status_proto.error_message(), status.message());
  EXPECT_EQ(status_proto.space(), status.error_space()->SpaceName());
  EXPECT_EQ(status_proto.payloads().size(), 1);
  ASSERT_NE(status_proto.payloads().find(kTypeUrl),
            status_proto.payloads().end());
  EXPECT_EQ(status_proto.payloads().at(kTypeUrl), kPayload);
}

TEST(StatusTest, RestoreFromOk) {
  ::asylo::StatusProto status_proto;
  status_proto.set_code(static_cast<int>(absl::StatusCode::kOk));
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(error::kCanonicalErrorSpaceName);

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_EQ(status.raw_code(), status_proto.code());
  // Error messages are ignored for OK status objects.
  EXPECT_TRUE(status.message().empty());
  EXPECT_EQ(status.error_space()->SpaceName(), status_proto.space());
}

TEST(StatusTest, RestoreFromNonOk) {
  ::asylo::StatusProto status_proto;
  status_proto.set_code(static_cast<int>(absl::StatusCode::kInvalidArgument));
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(error::kCanonicalErrorSpaceName);
  (*status_proto.mutable_payloads())[kTypeUrl] = kPayload;

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(status.message(), status_proto.error_message());
  EXPECT_THAT(status.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));
}

TEST(StatusTest, RestoreFromNonOkInvalidCanonicalCode) {
  // StatusProto with a mismatched error code and canonical code. The expected
  // equivalent canonical code is absl::StatusCode::kInvalidArgument.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(error::PosixError::P_EINVAL);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(error::kCanonicalErrorSpaceName);
  status_proto.set_canonical_code(
      static_cast<int>(absl::StatusCode::kInvalidArgument));

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(error::StatusError::RESTORE_ERROR));
}

TEST(StatusTest, RestoreFromUnknownErrorSpace) {
  // StatusProto with an unknown error space and a valid canonical code.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(42);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(kBadErrorSpace);
  status_proto.set_canonical_code(
      static_cast<int>(absl::StatusCode::kInvalidArgument));

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(status.message(), status_proto.error_message());
}

TEST(StatusTest, RestoreFromUnknownErrorSpaceMissingCanonicalCode) {
  // StatusProto with an unknown error space and no canonical code.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(42);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(kBadErrorSpace);

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(absl::StatusCode::kUnknown));
  EXPECT_EQ(status.message(), status_proto.error_message());
}

TEST(StatusTest, RestoreFromUnknownErrorSpaceInvalid) {
  // StatusProto with an OK error code from an unknown error space but a
  // mismatched canonical code.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(0);
  status_proto.set_space(kBadErrorSpace);
  status_proto.set_canonical_code(
      static_cast<int>(absl::StatusCode::kInvalidArgument));

  asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(error::StatusError::RESTORE_ERROR));

  // StatusProto with a non-OK error code from an unknown error space but an OK
  // canonical code.
  status_proto.Clear();
  status_proto.set_code(42);
  status_proto.set_canonical_code(0);

  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(error::StatusError::RESTORE_ERROR));
}

TEST(StatusTest, SaveToRestoreFromEndToEnd) {
  ::asylo::Status status1(absl::StatusCode::kInvalidArgument, kErrorMessage1);

  ::asylo::StatusProto status_proto;
  status1.SaveTo(&status_proto);

  ::asylo::Status status2;
  status2.RestoreFrom(status_proto);

  EXPECT_EQ(status1, status2);
}

TEST(StatusTest, SaveToRestoreFromEndToEndWithPayload) {
  ::asylo::Status status1(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  status1.SetPayload(kTypeUrl, absl::Cord(kPayload));

  ::asylo::StatusProto status_proto;
  status1.SaveTo(&status_proto);

  ::asylo::Status status2;
  status2.RestoreFrom(status_proto);

  EXPECT_EQ(status1, status2);
}

TEST(StatusTest, ConstructFromProtobufStatusOk) {
  ::google::protobuf::util::Status protobuf_status;
  ::asylo::Status status(protobuf_status);
  EXPECT_THAT(status, IsOk());
}

TEST(StatusTest, ConstructFromProtobufStatusNonOk) {
  ::google::protobuf::util::Status protobuf_status(
      ::google::protobuf::util::error::DATA_LOSS, kErrorMessage1);
  ::asylo::Status status(protobuf_status);

  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_EQ(status.raw_code(), protobuf_status.error_code());
  EXPECT_EQ(status.message(),
            std::string(protobuf_status.error_message()));
}

TEST(StatusTest, ConstructFromGrpcStatusOk) {
  // Default constructor for ::grpc::Status constructs an OK status object.
  ::grpc::Status grpc_status;
  ::asylo::Status status(grpc_status);

  EXPECT_THAT(status, IsOk());
}

TEST(StatusTest, ConstructFromGrpcStatusNonOk) {
  ::grpc::Status grpc_status(::grpc::StatusCode::INVALID_ARGUMENT,
                             kErrorMessage1);
  ::asylo::Status status(grpc_status);

  EXPECT_THAT(status, Not(IsOk()));

  // Constructed object is always in the canonical error space.
  EXPECT_EQ(status.raw_code(), grpc_status.error_code());
  EXPECT_EQ(status.message(), grpc_status.error_message());
}

TEST(StatusTest, ConvertToGrpcStatusOk) {
  ::asylo::Status status = ::asylo::OkStatus();
  ::grpc::Status grpc_status = status.ToOtherStatus<::grpc::Status>();

  EXPECT_EQ(status.ok(), grpc_status.ok());
  EXPECT_EQ(status.raw_code(), grpc_status.error_code());
  EXPECT_EQ(status.message(), grpc_status.error_message());
}

TEST(StatusTest, ConvertToGrpcStatusNonOk) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  ::grpc::Status grpc_status = status.ToOtherStatus<::grpc::Status>();

  EXPECT_EQ(status.ok(), grpc_status.ok());
  EXPECT_EQ(status.raw_code(), grpc_status.error_code());
  EXPECT_EQ(status.message(), grpc_status.error_message());
}

TEST(StatusTest, ConvertToGrpcStatusNonOkNonCanonical) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  ::grpc::Status grpc_status = status.ToOtherStatus<::grpc::Status>();

  // Status objects outside the canonical error space are converted before
  // type-casting:
  //   * Error code is converted to the equivalent code in the canonical error
  //   space
  //   * Error message is set to the ToString() representation
  EXPECT_EQ(grpc_status.ok(), status.ok());
  EXPECT_EQ(grpc_status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
  EXPECT_EQ(grpc_status.error_message(), status.ToString());
}

TEST(StatusTest, ConstructFromAbslStatusOk) {
  // Default constructor for ::absl::Status constructs an OK status object.
  ::absl::Status absl_status;
  ::asylo::Status status(absl_status);

  EXPECT_THAT(status, IsOk());
}

TEST(StatusTest, ConstructFromAbslStatusNonOk) {
  ::absl::Status absl_status(absl::StatusCode::kInvalidArgument,
                             kErrorMessage1);
  ::asylo::Status status(absl_status);

  EXPECT_THAT(status, Not(IsOk()));
  EXPECT_EQ(status.raw_code(), absl_status.raw_code());
  EXPECT_EQ(status.message(), absl_status.message());
}

TEST(StatusTest, TypeCastToAbslStatusOk) {
  ::asylo::Status status = ::asylo::OkStatus();
  ::absl::Status absl_status = status;

  EXPECT_EQ(status.ok(), absl_status.ok());
  EXPECT_EQ(status.raw_code(), absl_status.raw_code());
  EXPECT_EQ(status.message(), absl_status.message());
}

TEST(StatusTest, TypeCastToAbslStatusNonOk) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  ::absl::Status absl_status = status;

  EXPECT_EQ(status.ok(), absl_status.ok());
  EXPECT_EQ(status.raw_code(), absl_status.raw_code());
  EXPECT_EQ(status.message(), absl_status.message());
}

TEST(StatusTest, TypeCastToAbslStatusNonOkNonCanonical) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  ::absl::Status absl_status = status;

  // Status objects outside the canonical error space are converted before
  // type-casting:
  //   * Error code is converted to the equivalent code in the canonical error
  //   space
  //   * Error message is set to the ToString() representation
  EXPECT_EQ(absl_status.ok(), status.ok());
  EXPECT_EQ(absl_status.raw_code(),
            static_cast<int>(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.ToString(), HasSubstr(absl_status.message()));
}

TEST(StatusTest, TypeCastToAbslStatusOrNonOk) {
  ::asylo::Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  absl::StatusOr<std::string> absl_statusor = status;

  EXPECT_EQ(absl_statusor.ok(), status.ok());
  EXPECT_EQ(absl_statusor.status().raw_code(), status.raw_code());
  EXPECT_EQ(absl_statusor.status().message(), status.message());
}

TEST(StatusTest, TypeCastToAbslStatusOrNonOkNonCanonical) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  absl::StatusOr<std::string> absl_statusor = status;

  // Status objects outside the canonical error space are converted before
  // type-casting:
  //   * Error code is converted to the equivalent code in the canonical error
  //   space
  //   * Error message is set to the ToString() representation
  EXPECT_EQ(absl_statusor.ok(), status.ok());
  EXPECT_EQ(absl_statusor.status().raw_code(),
            static_cast<int>(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.ToString(), HasSubstr(absl_statusor.status().message()));
}

TEST(StatusTest, IsPositiveTest) {
  EXPECT_TRUE(OkStatus().Is(absl::StatusCode::kOk));
  EXPECT_TRUE(OkStatus().Is(error::GoogleError::OK));

  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_TRUE(invalid_arg_status.Is(absl::StatusCode::kInvalidArgument));
  EXPECT_TRUE(invalid_arg_status.Is(error::GoogleError::INVALID_ARGUMENT));

  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_TRUE(einval_status.Is(error::PosixError::P_EINVAL));
}

TEST(StatusTest, IsNegativeTest) {
  // Verify correctness of Is() within an error space.
  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_FALSE(invalid_arg_status.Is(absl::StatusCode::kOk));
  EXPECT_FALSE(invalid_arg_status.Is(error::GoogleError::OK));

  // Verify correctness of Is() across error spaces.
  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_FALSE(einval_status.Is(absl::StatusCode::kInvalidArgument));
  EXPECT_FALSE(einval_status.Is(error::GoogleError::INVALID_ARGUMENT));
}

TEST(StatusTest, WithPrependedContextCorrect) {
  Status status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  Status expected_status_with_context(absl::StatusCode::kInvalidArgument,
                                      kErrorMessage1WithPrependedContext);

  EXPECT_EQ(status.WithPrependedContext(kContext),
            expected_status_with_context);
}

TEST(StatusTest, StatusIsMatcher) {
  EXPECT_THAT(OkStatus(), StatusIs(absl::StatusCode::kOk));

  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_THAT(invalid_arg_status, StatusIs(absl::StatusCode::kInvalidArgument));

  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_THAT(einval_status, StatusIs(error::PosixError::P_EINVAL));
}

TEST(StatusTest, IsOkMatcher) {
  EXPECT_THAT(OkStatus(), IsOk());

  // Negation of IsOk() matcher.
  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_THAT(einval_status, Not(IsOk()));
}

TEST(StatusTest, MoveConstructorTest) {
  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  invalid_arg_status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  EXPECT_THAT(invalid_arg_status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(invalid_arg_status.GetPayload(kTypeUrl),
              Optional(absl::Cord(kPayload)));

  Status that(std::move(invalid_arg_status));

  EXPECT_THAT(that, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(that.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));
  EXPECT_THAT(invalid_arg_status, StatusIs(error::StatusError::MOVED));
  EXPECT_THAT(invalid_arg_status.GetPayload(kTypeUrl), Eq(absl::nullopt));
}

TEST(StatusTest, MoveAssignmentTestNonOk) {
  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  invalid_arg_status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  EXPECT_THAT(invalid_arg_status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(invalid_arg_status.GetPayload(kTypeUrl),
              Optional(absl::Cord(kPayload)));

  Status that(absl::StatusCode::kCancelled, kErrorMessage2);
  that = std::move(invalid_arg_status);

  EXPECT_THAT(that, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(that.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));
  EXPECT_THAT(invalid_arg_status, StatusIs(error::StatusError::MOVED));
  EXPECT_THAT(invalid_arg_status.GetPayload(kTypeUrl), Eq(absl::nullopt));
}

TEST(StatusTest, MoveAssignmentTestOk) {
  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  EXPECT_THAT(invalid_arg_status, StatusIs(absl::StatusCode::kInvalidArgument));

  Status ok = OkStatus();
  invalid_arg_status = std::move(ok);

  EXPECT_THAT(invalid_arg_status, StatusIs(absl::StatusCode::kOk, ""));
  EXPECT_THAT(ok, StatusIs(error::StatusError::MOVED));
}

TEST(StatusTest, CopyConstructorTestOk) {
  Status that(OkStatus());

  EXPECT_THAT(that, IsOk());
  EXPECT_TRUE(that.message().empty());
}

TEST(StatusTest, CopyConstructorTestNonOk) {
  Status invalid_arg_status(absl::StatusCode::kInvalidArgument, kErrorMessage1);
  invalid_arg_status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  EXPECT_THAT(invalid_arg_status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(invalid_arg_status.GetPayload(kTypeUrl),
              Optional(absl::Cord(kPayload)));

  Status that(invalid_arg_status);

  EXPECT_THAT(that, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(that.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));
}

TEST(StatusTest, ConstructorWithErrorSpaceOk) {
  Status that(error::error_enum_traits<absl::StatusCode>::get_error_space(),
              static_cast<int>(absl::StatusCode::kOk),
              "This message is not copied");
  EXPECT_TRUE(that.message().empty());
  EXPECT_THAT(that, IsOk());
}

TEST(StatusTest, ConstructorWithErrorSpaceNotOk) {
  Status that(error::error_enum_traits<absl::StatusCode>::get_error_space(),
              static_cast<int>(absl::StatusCode::kInvalidArgument),
              "This message is copied");
  EXPECT_THAT(that, StatusIs(absl::StatusCode::kInvalidArgument,
                             "This message is copied"));
}

TEST(StatusTest, GetPayloadReturnsNulloptIfNoTypeUrlMatch) {
  Status status = OkStatus();
  EXPECT_EQ(status.GetPayload(kTypeUrl), absl::nullopt);
}

TEST(StatusTest, SetPayloadsCanBeFetchedWithGetPayload) {
  Status status = absl::InvalidArgumentError(kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  EXPECT_THAT(status.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));
}

TEST(StatusTest, ErasePayloadReturnsFalseIfPayloadNotPresent) {
  Status status = absl::InvalidArgumentError(kErrorMessage1);
  EXPECT_FALSE(status.ErasePayload(kTypeUrl));
}

TEST(StatusTest, ErasePayloadReturnsTrueIfPayloadPresent) {
  Status status = absl::InvalidArgumentError(kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  EXPECT_TRUE(status.ErasePayload(kTypeUrl));
}

TEST(StatusTest, ErasePayloadRemovesPayload) {
  Status status = absl::InvalidArgumentError(kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));
  ASSERT_THAT(status.GetPayload(kTypeUrl), Optional(absl::Cord(kPayload)));

  status.ErasePayload(kTypeUrl);
  EXPECT_EQ(status.GetPayload(kTypeUrl), absl::nullopt);
}

TEST(StatusTest, ForEachPayloadVisitsEveryPayloadExactlyOnce) {
  Status status = absl::InvalidArgumentError(kErrorMessage1);
  status.SetPayload(kTypeUrl, absl::Cord(kPayload));

  int counter = 0;
  status.ForEachPayload(
      [&counter](absl::string_view type_url, const absl::Cord &payload) {
        ASSERT_EQ(type_url, kTypeUrl);
        EXPECT_EQ(payload, kPayload);
        ++counter;
      });
  EXPECT_EQ(counter, 1);
}

}  // namespace
}  // namespace asylo
