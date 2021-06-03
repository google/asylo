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

#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client.h"

#include <memory>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client_config.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_parser.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_service.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_service_server.h"
#include "asylo/util/remote/grpc_channel_builder.h"
#include "asylo/util/remote/grpc_server_main_wrapper.h"
#include "opencensus/stats/stats.h"
#include "opencensus/tags/tag_key.h"

namespace asylo {
namespace primitives {
namespace {

using ::opencensus::stats::ViewData;
using ::opencensus::stats::ViewDescriptor;

using ::testing::_;
using ::testing::Eq;
using ::testing::Return;
using ::testing::Test;

class MockExporter : public ::opencensus::stats::StatsExporter::Handler {
 public:
  static void Register(
      MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> *output) {
    opencensus::stats::StatsExporter::RegisterPushHandler(
        absl::make_unique<MockExporter>(output));
  }

  explicit MockExporter(
      MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> *output)
      : output_(output) {}

  void ExportViewData(
      const std::vector<std::pair<ViewDescriptor, ViewData>> &data) override {
    for (const auto &datum : data) {
      output_->Lock()->emplace_back(datum.first, datum.second);
    }
  }

 private:
  MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> *output_;
};

class OpenCensusClientTest : public ::testing::Test {
 public:
  OpenCensusClientTest()
      : ::testing::Test(),
        output_(std::vector<std::pair<ViewDescriptor, ViewData>>({})) {}

  void SetUp() override {
    auto mock_parser = absl::make_unique<MockProcSystemParser>();
    EXPECT_CALL(*mock_parser, ReadProcStat(_))
        .WillRepeatedly(Return(mock_parser->stat_contents()));
    // Save raw pointer before std::move for the test to use.
    mock_parser_ = mock_parser.get();
    auto mock_server_request =
        GrpcServerMainWrapper<MockProcSystemServiceServer>::Create(
            0, std::move(mock_parser), mock_parser_->kExpectedPid);
    CHECK(mock_server_request.ok());
    mock_server_ = std::move(mock_server_request.value());

    server_address_ = absl::StrCat("[::]:", mock_server_->port());

    MockExporter::Register(&output_);
  }

  MockProcSystemParser *mock_parser_;
  MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> output_;

  std::string server_address_;

 private:
  std::unique_ptr<GrpcServerMainWrapper<MockProcSystemServiceServer>>
      mock_server_;
};

// Test ensures that we can get metrics from a MockProcSystemServiceServer and
// that metrics are equivalent to expected values.
TEST_F(OpenCensusClientTest, SuccessfullyGetsMetrics) {
  auto channel_request = GrpcChannelBuilder::BuildChannel(server_address_);
  ASSERT_TRUE(channel_request.ok());

  OpenCensusClientConfig config;
  config.granularity = absl::Seconds(1);
  config.view_name_root = "test_root";

  auto opencensus_client =
      OpenCensusClient::Create(channel_request.value(), config);

  while (output_.ReaderLock()->size() < 14) {
    absl::SleepFor(absl::Seconds(1));
  }

  const std::pair<std::vector<std::string>, int64_t> kExpectedMinorFaults(
      {{"OpenCensusClient::RecordMinorFaults"}, mock_parser_->kExpectedMinFlt});
  const std::pair<std::vector<std::string>, int64_t> kExpectedMajorFaults(
      {{"OpenCensusClient::RecordMajorFaults"}, mock_parser_->kExpectedMajFlt});
  const std::pair<std::vector<std::string>, int64_t>
      kExpectedChildrenMinorFaults(
          {{"OpenCensusClient::RecordChildrenMinorFaults"},
           mock_parser_->kExpectedCMinFlt});
  const std::pair<std::vector<std::string>, int64_t>
      kExpectedChildrenMajorFaults(
          {{"OpenCensusClient::RecordChildrenMajorFaults"},
           mock_parser_->kExpectedCMajFlt});
  const std::pair<std::vector<std::string>, int64_t> kExpectedUTime(
      {{"OpenCensusClient::RecordUTime"}, mock_parser_->kExpectedUTime});
  const std::pair<std::vector<std::string>, int64_t> kExpectedSTime(
      {{"OpenCensusClient::RecordSTime"}, mock_parser_->kExpectedSTime});
  const std::pair<std::vector<std::string>, int64_t> kExpectedCUTime(
      {{"OpenCensusClient::RecordCUTime"}, mock_parser_->kExpectedCUTime});
  const std::pair<std::vector<std::string>, int64_t> kExpectedCSTime(
      {{"OpenCensusClient::RecordCSTime"}, mock_parser_->kExpectedCSTime});
  const std::pair<std::vector<std::string>, int64_t> kExpectedStartTime(
      {{"OpenCensusClient::RecordStartTime"},
       mock_parser_->kExpectedStartTime});
  const std::pair<std::vector<std::string>, int64_t> kExpectedVSize(
      {{"OpenCensusClient::RecordVSize"}, mock_parser_->kExpectedVSize});
  const std::pair<std::vector<std::string>, int64_t> kExpectedRss(
      {{"OpenCensusClient::RecordRss"}, mock_parser_->kExpectedRss});
  const std::pair<std::vector<std::string>, int64_t> kExpectedRssSLim(
      {{"OpenCensusClient::RecordRssSLim"}, mock_parser_->kExpectedRssSLim});
  const std::pair<std::vector<std::string>, int64_t> kExpectedGuestTime(
      {{"OpenCensusClient::RecordGuestTime"},
       mock_parser_->kExpectedGuestTime});
  const std::pair<std::vector<std::string>, int64_t> kExpectedChildrenGuestTime(
      {{"OpenCensusClient::RecordChildrenGuestTime"},
       mock_parser_->kExpectedCguestTime});

  ASSERT_THAT(output_.ReaderLock()->size(), Eq(14));
  std::vector<std::pair<std::vector<std::string>, int64_t>> collected_metrics;
  for (const auto &datum : *output_.ReaderLock()) {
    for (const auto &data : datum.second.int_data()) {
      collected_metrics.push_back(data);
    }
  }
  EXPECT_THAT(
      collected_metrics,
      ::testing::UnorderedElementsAre(
          kExpectedMinorFaults, kExpectedChildrenMinorFaults,
          kExpectedMajorFaults, kExpectedChildrenMajorFaults, kExpectedUTime,
          kExpectedSTime, kExpectedCUTime, kExpectedCSTime, kExpectedStartTime,
          kExpectedVSize, kExpectedRss, kExpectedRssSLim, kExpectedGuestTime,
          kExpectedChildrenGuestTime));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
