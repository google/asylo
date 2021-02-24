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

#include "asylo/platform/primitives/remote/metrics/clients/proc_system_service_client.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_service.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.grpc.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_mock.grpc.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/status_helpers.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace primitives {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgPointee;

class ProcSystemServiceClientTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto mock_parser = absl::make_unique<MockProcSystemParser>();
    EXPECT_CALL(*mock_parser, ReadProcStat(_))
        .WillOnce(Return(mock_parser->stat_contents()));

    // |mock_parser| is consumed by |mock_service|. Need a second instance for
    // comparison.
    const auto comparison_parser = mock_parser.get();

    MockProcSystemService mock_service(std::move(mock_parser),
                                       comparison_parser->kExpectedPid);

    ASYLO_ASSERT_OK(ConvertStatus<asylo::Status>(mock_service.GetProcStat(
        &context_, &proc_stat_request_, &proc_stat_response_)));
  }

 protected:
  ::grpc::ServerContext context_;
  ProcStatRequest proc_stat_request_;
  ProcStatResponse proc_stat_response_;
};

TEST_F(ProcSystemServiceClientTest, ReturnsProcStat) {
  auto mock_stub = std::make_shared<MockProcSystemServiceStub>();
  EXPECT_CALL(*mock_stub, GetProcStat)
      .WillOnce(DoAll(SetArgPointee<2>(proc_stat_response_),
                      Return(::grpc::Status::OK)));
  ProcSystemServiceClient proc_client(mock_stub);

  ProcStatResponse response;
  ASYLO_ASSERT_OK_AND_ASSIGN(response, proc_client.GetProcStat());
  EXPECT_THAT(proc_stat_response_, EqualsProto(response));
}

TEST(ProcSystemServiceClientTestNoFixture, HandlesGetProcStatError) {
  auto mock_stub = std::make_shared<MockProcSystemServiceStub>();
  EXPECT_CALL(*mock_stub, GetProcStat)
      .WillOnce(
          Return(::grpc::Status(::grpc::StatusCode::UNKNOWN, "BadError")));
  ProcSystemServiceClient proc_client(mock_stub);

  auto proc_or_request = proc_client.GetProcStat();
  ASSERT_THAT(proc_or_request.status(),
              Eq(::asylo::Status(absl::StatusCode::kUnknown, "BadError")));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
