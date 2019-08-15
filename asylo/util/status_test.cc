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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/posix_error_space.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kErrorMessage1[] = "Bad foo argument";
constexpr char kErrorMessage2[] = "Internal foobar error";

constexpr char kBadErrorSpace[] = "Foo bar error space";

constexpr char kContext[] = "At index 1";
constexpr char kErrorMessage1WithPrependedContext[] =
    "At index 1: Bad foo argument";

TEST(StatusTest, OkSuccess) { EXPECT_TRUE(::asylo::Status::OkStatus().ok()); }

TEST(StatusTest, OkFailure) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  EXPECT_FALSE(status.ok());
}

TEST(StatusTest, GetErrorCodeOkStatus) {
  EXPECT_EQ(::asylo::Status::OkStatus().error_code(), error::GoogleError::OK);
}

TEST(StatusTest, GetErrorCodeNonOkStatus) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  EXPECT_EQ(status.error_code(), error::GoogleError::INVALID_ARGUMENT);
}

TEST(StatusTest, GetErrorMessageOkStatus) {
  EXPECT_TRUE(Status::OkStatus().error_message().empty());
}

TEST(StatusTest, GetErrorMessageNonOkStatus) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  EXPECT_EQ(status.error_message(), kErrorMessage1);
}

TEST(StatusTest, GetErrorSpaceOkStatus) {
  const error::ErrorSpace *error_space = Status::OkStatus().error_space();
  EXPECT_EQ(error_space->SpaceName(), error::kCanonicalErrorSpaceName);
}

TEST(StatusTest, GetErrorSpaceNonOkStatus) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  const error::ErrorSpace *error_space = status.error_space();
  EXPECT_EQ(error_space->SpaceName(), error::kCanonicalErrorSpaceName);
}

TEST(StatusTest, ToStringOkStatus) {
  ::asylo::Status status = Status::OkStatus();
  std::string error_code_name =
      status.error_space()->String(status.error_code());

  // The ToString() representation for an ok Status should contain the error
  // code name.
  std::string status_rep = status.ToString();
  EXPECT_NE(status_rep.find(error_code_name), std::string::npos);
}

TEST(StatusTest, ToStringNonOkStatus) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  std::string error_code_name =
      status.error_space()->String(status.error_code());
  std::string error_space_name = status.error_space()->SpaceName();
  // The format of ToString() is subject to change for a non-ok Status, but it
  // should contain the error space name, the error code name, and the error
  // message.
  std::string status_rep = status.ToString();
  EXPECT_NE(status_rep.find(error_space_name), std::string::npos);
  EXPECT_NE(status_rep.find(error_code_name), std::string::npos);
  EXPECT_NE(status_rep.find(std::string(status.error_message())),
            std::string::npos);
}

TEST(StatusTest, Equality) {
  ::asylo::Status ok_status = Status::OkStatus();
  Status error_status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);

  EXPECT_TRUE(ok_status == ok_status);
  EXPECT_TRUE(error_status == error_status);
  EXPECT_FALSE(ok_status == error_status);
}

TEST(StatusTest, Inequality) {
  asylo::Status ok_status = Status::OkStatus();
  asylo::Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                                   kErrorMessage1);
  asylo::Status internal_status(error::GoogleError::INTERNAL, kErrorMessage2);

  EXPECT_FALSE(ok_status != ok_status);
  EXPECT_FALSE(invalid_arg_status != invalid_arg_status);

  EXPECT_TRUE(ok_status != invalid_arg_status);
  EXPECT_TRUE(invalid_arg_status != ok_status);

  EXPECT_TRUE(invalid_arg_status != internal_status);
  EXPECT_TRUE(internal_status != invalid_arg_status);
}

TEST(StatusTest, ToCanonicalOk) {
  EXPECT_EQ(Status::OkStatus().ToCanonical(), Status::OkStatus());
}

TEST(StatusTest, ToCanonicalNonOk) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
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
            Status(error::GoogleError::INVALID_ARGUMENT, status.ToString()));
}

TEST(StatusTest, CanonicalCodeOk) {
  EXPECT_EQ(Status::OkStatus().CanonicalCode(), error::GoogleError::OK);
}

TEST(StatusTest, CanonicalCodeNonOk) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  EXPECT_EQ(status.CanonicalCode(), status.error_code());
}

TEST(StatusTest, CanonicalCodeNonOkNonCanonical) {
  ::asylo::Status status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_EQ(status.CanonicalCode(), error::GoogleError::INVALID_ARGUMENT);
}

TEST(StatusTest, SaveTo) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  ::asylo::StatusProto status_proto;
  status.SaveTo(&status_proto);

  EXPECT_EQ(status_proto.code(), status.error_code());
  EXPECT_EQ(status_proto.error_message(), status.error_message());
  EXPECT_EQ(status_proto.space(), status.error_space()->SpaceName());
}

TEST(StatusTest, RestoreFromOk) {
  ::asylo::StatusProto status_proto;
  status_proto.set_code(error::GoogleError::OK);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(error::kCanonicalErrorSpaceName);

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_EQ(status.error_code(), status_proto.code());
  // Error messages are ignored for OK status objects.
  EXPECT_TRUE(status.error_message().empty());
  EXPECT_EQ(status.error_space()->SpaceName(), status_proto.space());
}

TEST(StatusTest, RestoreFromNonOk) {
  ::asylo::StatusProto status_proto;
  status_proto.set_code(error::GoogleError::INVALID_ARGUMENT);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(error::kCanonicalErrorSpaceName);

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_EQ(status.error_message(), status_proto.error_message());
}

TEST(StatusTest, RestoreFromNonOkInvalidCanonicalCode) {
  // StatusProto with a mismatched error code and canonical code. The expected
  // equivalent canonical code is error::GoogleError::INVALID_ARGUMENT.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(error::PosixError::P_EINVAL);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(error::kCanonicalErrorSpaceName);
  status_proto.set_canonical_code(error::GoogleError::UNAUTHENTICATED);

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
  status_proto.set_canonical_code(error::GoogleError::INVALID_ARGUMENT);

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_EQ(status.error_message(), status_proto.error_message());
}

TEST(StatusTest, RestoreFromUnknownErrorSpaceMissingCanonicalCode) {
  // StatusProto with an unknown error space and no canonical code.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(42);
  status_proto.set_error_message(kErrorMessage1);
  status_proto.set_space(kBadErrorSpace);

  ::asylo::Status status;
  status.RestoreFrom(status_proto);

  EXPECT_THAT(status, StatusIs(error::GoogleError::UNKNOWN));
  EXPECT_EQ(status.error_message(), status_proto.error_message());
}

TEST(StatusTest, RestoreFromUnknownErrorSpaceInvalid) {
  // StatusProto with an OK error code from an unknown error space but a
  // mismatched canonical code.
  ::asylo::StatusProto status_proto;
  status_proto.set_code(0);
  status_proto.set_space(kBadErrorSpace);
  status_proto.set_canonical_code(error::GoogleError::INVALID_ARGUMENT);

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
  ::asylo::Status status1(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);

  ::asylo::StatusProto status_proto;
  status1.SaveTo(&status_proto);

  ::asylo::Status status2;
  status2.RestoreFrom(status_proto);

  EXPECT_EQ(status1, status2);
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
  EXPECT_EQ(status.error_code(), grpc_status.error_code());
  EXPECT_EQ(status.error_message(), grpc_status.error_message());
}

TEST(StatusTest, ConvertToGrpcStatusOk) {
  ::asylo::Status status = ::asylo::Status::OkStatus();
  ::grpc::Status grpc_status = status.ToOtherStatus<::grpc::Status>();

  EXPECT_EQ(status.ok(), grpc_status.ok());
  EXPECT_EQ(status.error_code(), grpc_status.error_code());
  EXPECT_EQ(status.error_message(), grpc_status.error_message());
}

TEST(StatusTest, ConvertToGrpcStatusNonOk) {
  ::asylo::Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  ::grpc::Status grpc_status = status.ToOtherStatus<::grpc::Status>();

  EXPECT_EQ(status.ok(), grpc_status.ok());
  EXPECT_EQ(status.error_code(), grpc_status.error_code());
  EXPECT_EQ(status.error_message(), grpc_status.error_message());
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

TEST(StatusTest, IsPositiveTest) {
  EXPECT_TRUE(Status::OkStatus().Is(error::GoogleError::OK));

  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_TRUE(invalid_arg_status.Is(error::GoogleError::INVALID_ARGUMENT));

  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_TRUE(einval_status.Is(error::PosixError::P_EINVAL));
}

TEST(StatusTest, IsNegativeTest) {
  // Verify correctness of Is() within an error space.
  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_FALSE(invalid_arg_status.Is(error::GoogleError::OK));

  // Verify correctness of Is() across error spaces.
  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_FALSE(einval_status.Is(error::GoogleError::INVALID_ARGUMENT));
}

TEST(StatusTest, WithPrependedContextCorrect) {
  Status status(error::GoogleError::INVALID_ARGUMENT, kErrorMessage1);
  Status expected_status_with_context(error::GoogleError::INVALID_ARGUMENT,
                                      kErrorMessage1WithPrependedContext);

  EXPECT_EQ(status.WithPrependedContext(kContext),
            expected_status_with_context);
}

TEST(StatusTest, StatusIsMatcher) {
  EXPECT_THAT(Status::OkStatus(), StatusIs(error::GoogleError::OK));

  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_THAT(invalid_arg_status,
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_THAT(einval_status, StatusIs(error::PosixError::P_EINVAL));
}

TEST(StatusTest, IsOkMatcher) {
  EXPECT_THAT(Status::OkStatus(), IsOk());

  // Negation of IsOk() matcher.
  Status einval_status(error::PosixError::P_EINVAL, kErrorMessage1);
  EXPECT_THAT(einval_status, Not(IsOk()));
}

TEST(StatusTest, MoveConstructorTest) {
  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_THAT(invalid_arg_status,
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  Status that(std::move(invalid_arg_status));

  EXPECT_THAT(that, StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_THAT(invalid_arg_status, StatusIs(error::StatusError::MOVED));
}

TEST(StatusTest, MoveAssignmentTestNonOk) {
  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_THAT(invalid_arg_status,
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  Status that(error::GoogleError::CANCELLED, kErrorMessage2);
  that = std::move(invalid_arg_status);

  EXPECT_THAT(that, StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_THAT(invalid_arg_status, StatusIs(error::StatusError::MOVED));
}

TEST(StatusTest, MoveAssignmentTestOk) {
  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_THAT(invalid_arg_status,
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  Status ok = Status::OkStatus();
  invalid_arg_status = std::move(ok);

  EXPECT_THAT(invalid_arg_status, StatusIs(error::GoogleError::OK, ""));
  EXPECT_THAT(ok, StatusIs(error::StatusError::MOVED));
}

TEST(StatusTest, CopyConstructorTestOk) {
  Status that(Status::OkStatus());

  EXPECT_THAT(that, IsOk());
  EXPECT_TRUE(that.error_message().empty());
}

TEST(StatusTest, CopyConstructorTestNonOk) {
  Status invalid_arg_status(error::GoogleError::INVALID_ARGUMENT,
                            kErrorMessage1);
  EXPECT_THAT(invalid_arg_status,
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  Status that(invalid_arg_status);

  EXPECT_THAT(that, StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(StatusTest, ConstructorWithErrorSpaceOk) {
  Status that(error::error_enum_traits<error::GoogleError>::get_error_space(),
              error::GoogleError::OK, "This message is not copied");
  EXPECT_TRUE(that.error_message().empty());
  EXPECT_THAT(that, IsOk());
}

TEST(StatusTest, ConstructorWithErrorSpaceNotOk) {
  Status that(error::error_enum_traits<error::GoogleError>::get_error_space(),
              error::GoogleError::INVALID_ARGUMENT, "This message is copied");
  EXPECT_THAT(that, StatusIs(error::GoogleError::INVALID_ARGUMENT,
                             "This message is copied"));
}

}  // namespace
}  // namespace asylo
