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

#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/notification.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client_config.h"
#include "asylo/platform/primitives/remote/metrics/clients/proc_system_service_client.h"
#include "asylo/util/path.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"
#include "opencensus/stats/stats.h"
#include "opencensus/tags/tag_key.h"

namespace asylo {
namespace primitives {

using ::opencensus::stats::MeasureDouble;
using ::opencensus::stats::MeasureInt64;
using ::opencensus::stats::Record;
using ::opencensus::stats::ViewDescriptor;
using ::opencensus::tags::TagKey;

OpenCensusClient::~OpenCensusClient() { StopCensus(); }

std::unique_ptr<OpenCensusClient> OpenCensusClient::Create(
    const std::shared_ptr<::grpc::Channel> &channel,
    const OpenCensusClientConfig &config) {
  // Create the client.
  std::unique_ptr<OpenCensusClient> client(
      new OpenCensusClient(channel, config));

  // Register Measures.
  client->MinorFaultsMeasure();
  client->ChildrenMinorFaultsMeasure();
  client->MajorFaultsMeasure();
  client->ChildrenMajorFaultsMeasure();
  client->UTimeMeasure();
  client->STimeMeasure();
  client->CUTimeMeasure();
  client->CSTimeMeasure();
  client->StartTimeMeasure();
  client->VSizeMeasure();
  client->RssMeasure();
  client->RssSLimMeasure();
  client->GuestTimeMeasure();
  client->ChildrenGuestTimeMeasure();

  // Register Views.
  client->RegisterMinorFaultsView();
  client->RegisterChildrenMinorFaultsView();
  client->RegisterMajorFaultsView();
  client->RegisterChildrenMajorFaultsView();
  client->RegisterUTimeView();
  client->RegisterSTimeView();
  client->RegisterCUTimeView();
  client->RegisterCSTimeView();
  client->RegisterStartTimeView();
  client->RegisterVSizeView();
  client->RegisterRssView();
  client->RegisterRssSLimView();
  client->RegisterGuestTimeView();
  client->RegisterChildrenGuestTimeView();

  // Start the census.
  client->StartCensus();

  return client;
}

::asylo::Status OpenCensusClient::StartCensus() {
  *record_.Lock() = true;

  census_thread_ = absl::make_unique<Thread>([this]() -> void {
    std::vector<Recorder> recorders({
        &OpenCensusClient::RecordMinorFaults,
        &OpenCensusClient::RecordChildrenMinorFaults,
        &OpenCensusClient::RecordMajorFaults,
        &OpenCensusClient::RecordChildrenMajorFaults,
        &OpenCensusClient::RecordUTime,
        &OpenCensusClient::RecordSTime,
        &OpenCensusClient::RecordCUTime,
        &OpenCensusClient::RecordCSTime,
        &OpenCensusClient::RecordStartTime,
        &OpenCensusClient::RecordVSize,
        &OpenCensusClient::RecordRss,
        &OpenCensusClient::RecordRssSLim,
        &OpenCensusClient::RecordGuestTime,
        &OpenCensusClient::RecordChildrenGuestTime,
    });

    // Do not hold a lock on record_ so that StopCensus can set it to false.
    while (*record_.ReaderLock()) {
      auto response_or_request = proc_client_->GetProcStat();
      if (!response_or_request.ok()) {
        LOG(ERROR) << response_or_request.status();
        *record_.Lock() = false;
        break;
      }

      for (auto recorder : recorders) {
        ((this)->*(recorder))(response_or_request.value());
      }

      absl::SleepFor(config_.granularity);
    }
  });
  return ::absl::OkStatus();
}

void OpenCensusClient::StopCensus() {
  *record_.Lock() = false;
  if (census_thread_ != nullptr) {
    census_thread_->Join();
    census_thread_ = nullptr;
  }
}

void OpenCensusClient::RecordMinorFaults(
    const ProcStatResponse &response) const {
  Record({{MinorFaultsMeasure(), response.proc_stat().minflt()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordChildrenMinorFaults(
    const ProcStatResponse &response) const {
  Record({{ChildrenMinorFaultsMeasure(), response.proc_stat().cminflt()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordMajorFaults(
    const ProcStatResponse &response) const {
  Record({{MajorFaultsMeasure(), response.proc_stat().majflt()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordChildrenMajorFaults(
    const ProcStatResponse &response) const {
  Record({{ChildrenMajorFaultsMeasure(), response.proc_stat().cmajflt()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordUTime(const ProcStatResponse &response) const {
  Record({{UTimeMeasure(), response.proc_stat().utime()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordSTime(const ProcStatResponse &response) const {
  Record({{STimeMeasure(), response.proc_stat().stime()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordCUTime(const ProcStatResponse &response) const {
  Record({{CUTimeMeasure(), response.proc_stat().cutime()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordCSTime(const ProcStatResponse &response) const {
  Record({{CSTimeMeasure(), response.proc_stat().cstime()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordStartTime(const ProcStatResponse &response) const {
  Record({{StartTimeMeasure(), response.proc_stat().starttime()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordVSize(const ProcStatResponse &response) const {
  Record({{VSizeMeasure(), response.proc_stat().vsize()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordRss(const ProcStatResponse &response) const {
  Record({{RssMeasure(), response.proc_stat().rss()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordRssSLim(const ProcStatResponse &response) const {
  Record({{RssSLimMeasure(), response.proc_stat().rsslim()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordGuestTime(const ProcStatResponse &response) const {
  Record({{GuestTimeMeasure(), response.proc_stat().guest_time()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

void OpenCensusClient::RecordChildrenGuestTime(
    const ProcStatResponse &response) const {
  Record({{ChildrenGuestTimeMeasure(), response.proc_stat().cguest_time()}},
         {{MethodKey(), absl::StrCat("OpenCensusClient::", __func__)}});
}

TagKey OpenCensusClient::MethodKey() const {
  static const auto key = TagKey::Register("method");
  return key;
}

MeasureInt64 OpenCensusClient::MinorFaultsMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kMinorFaultsMeasureName, kMinorFaultsMeasureDescription, units::kCount);
  return measure;
}

MeasureInt64 OpenCensusClient::ChildrenMinorFaultsMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kChildrenMinorFaultsMeasureName, kChildrenMinorFaultsMeasureDescription,
      units::kCount);
  return measure;
}

MeasureInt64 OpenCensusClient::MajorFaultsMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kMajorFaultsMeasureName, kMajorFaultsMeasureDescription, units::kCount);
  return measure;
}

MeasureInt64 OpenCensusClient::ChildrenMajorFaultsMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kChildrenMajorFaultsMeasureName, kChildrenMajorFaultsMeasureDescription,
      units::kCount);
  return measure;
}

MeasureInt64 OpenCensusClient::UTimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kUTimeMeasureName, kUTimeMeasureDescription, units::kTicks);
  return measure;
}

MeasureInt64 OpenCensusClient::STimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kSTimeMeasureName, kSTimeMeasureDescription, units::kTicks);
  return measure;
}

MeasureInt64 OpenCensusClient::CUTimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kCUTimeMeasureName, kCUTimeMeasureDescription, units::kTicks);
  return measure;
}

MeasureInt64 OpenCensusClient::CSTimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kCSTimeMeasureName, kCSTimeMeasureDescription, units::kTicks);
  return measure;
}

MeasureInt64 OpenCensusClient::StartTimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kStartTimeMeasureName, kStartTimeMeasureDescription, units::kTicks);
  return measure;
}

MeasureInt64 OpenCensusClient::VSizeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kVSizeMeasureName, kVSizeMeasureDescription, units::kBytes);
  return measure;
}

MeasureInt64 OpenCensusClient::RssMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kRssMeasureName, kRssMeasureDescription, units::kCount);
  return measure;
}

MeasureInt64 OpenCensusClient::RssSLimMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kRssSLimMeasureName, kRssSLimMeasureDescription, units::kCount);
  return measure;
}

MeasureInt64 OpenCensusClient::GuestTimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kGuestTimeMeasureName, kGuestTimeMeasureDescription, units::kTicks);
  return measure;
}

MeasureInt64 OpenCensusClient::ChildrenGuestTimeMeasure() const {
  static const auto measure = MeasureInt64::Register(
      kChildrenGuestTimeMeasureName, kChildrenGuestTimeMeasureDescription,
      units::kTicks);
  return measure;
}

void OpenCensusClient::RegisterView(
    ViewDescriptor *view_descriptor, const absl::string_view measure_name,
    const absl::string_view measure_description) {
  *view_descriptor =
      ViewDescriptor()
          .set_name(asylo::JoinPath(config_.view_name_root, measure_name))
          .set_description(measure_description)
          .set_measure(measure_name)
          .set_aggregation(opencensus::stats::Aggregation::LastValue())
          .add_column(MethodKey());
  view_descriptor->RegisterForExport();
}

void OpenCensusClient::RegisterMinorFaultsView() {
  RegisterView(&minor_faults_view_descriptor_, kMinorFaultsMeasureName,
               kMinorFaultsMeasureDescription);
}

void OpenCensusClient::RegisterChildrenMinorFaultsView() {
  RegisterView(&children_minor_faults_view_descriptor_,
               kChildrenMinorFaultsMeasureName,
               kChildrenMinorFaultsMeasureDescription);
}

void OpenCensusClient::RegisterMajorFaultsView() {
  RegisterView(&major_faults_view_descriptor_, kMajorFaultsMeasureName,
               kMajorFaultsMeasureDescription);
}

void OpenCensusClient::RegisterChildrenMajorFaultsView() {
  RegisterView(&children_major_faults_view_descriptor_,
               kChildrenMajorFaultsMeasureName,
               kChildrenMajorFaultsMeasureDescription);
}

void OpenCensusClient::RegisterUTimeView() {
  RegisterView(&utime_view_descriptor_, kUTimeMeasureName,
               kUTimeMeasureDescription);
}

void OpenCensusClient::RegisterSTimeView() {
  RegisterView(&stime_view_descriptor_, kSTimeMeasureName,
               kSTimeMeasureDescription);
}

void OpenCensusClient::RegisterCUTimeView() {
  RegisterView(&cutime_view_descriptor_, kCUTimeMeasureName,
               kCUTimeMeasureDescription);
}

void OpenCensusClient::RegisterCSTimeView() {
  RegisterView(&cstime_view_descriptor_, kCSTimeMeasureName,
               kCSTimeMeasureDescription);
}

void OpenCensusClient::RegisterStartTimeView() {
  RegisterView(&start_time_view_descriptor_, kStartTimeMeasureName,
               kStartTimeMeasureDescription);
}

void OpenCensusClient::RegisterVSizeView() {
  RegisterView(&vsize_view_descriptor_, kVSizeMeasureName,
               kVSizeMeasureDescription);
}

void OpenCensusClient::RegisterRssView() {
  RegisterView(&rss_view_descriptor_, kRssMeasureName, kRssMeasureDescription);
}

void OpenCensusClient::RegisterRssSLimView() {
  RegisterView(&rss_slim_view_descriptor_, kRssSLimMeasureName,
               kRssSLimMeasureDescription);
}

void OpenCensusClient::RegisterGuestTimeView() {
  RegisterView(&guest_time_view_descriptor_, kGuestTimeMeasureName,
               kGuestTimeMeasureDescription);
}

void OpenCensusClient::RegisterChildrenGuestTimeView() {
  RegisterView(&children_guest_time_view_descriptor_,
               kChildrenGuestTimeMeasureName,
               kChildrenGuestTimeMeasureDescription);
}

}  // namespace primitives
}  // namespace asylo
