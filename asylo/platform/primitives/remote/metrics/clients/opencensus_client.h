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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_OPENCENSUS_CLIENT_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_OPENCENSUS_CLIENT_H_

#include "absl/strings/string_view.h"
#include "absl/synchronization/notification.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client_config.h"
#include "asylo/platform/primitives/remote/metrics/clients/proc_system_service_client.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/thread.h"
#include "opencensus/stats/stats.h"
#include "opencensus/tags/tag_key.h"

namespace asylo {
namespace primitives {

namespace units {

ABSL_CONST_INIT static const absl::string_view kCount = "1";
ABSL_CONST_INIT static const absl::string_view kBytes = "Bytes";
ABSL_CONST_INIT static const absl::string_view kTicks = "Clock Ticks";

}  // namespace units

class OpenCensusClient {
 public:
  ~OpenCensusClient();
  static std::unique_ptr<OpenCensusClient> Create(
      const std::shared_ptr<::grpc::Channel> &channel,
      const OpenCensusClientConfig &config);

 private:
  OpenCensusClient() = delete;
  OpenCensusClient(const OpenCensusClient &other) = delete;
  OpenCensusClient &operator=(const OpenCensusClient &other) = delete;

  explicit OpenCensusClient(const std::shared_ptr<::grpc::Channel> &channel,
                            const OpenCensusClientConfig &config)
      : proc_client_(absl::make_unique<ProcSystemServiceClient>(channel)),
        config_(config) {}

  // Methods responsible for starting and stopping the Census.
  ::asylo::Status StartCensus();
  void StopCensus();

  // Tag Keys
  ::opencensus::tags::TagKey MethodKey() const;

  // Measure metric generation
  ::opencensus::stats::MeasureInt64 MinorFaultsMeasure() const;
  ::opencensus::stats::MeasureInt64 ChildrenMinorFaultsMeasure() const;
  ::opencensus::stats::MeasureInt64 MajorFaultsMeasure() const;
  ::opencensus::stats::MeasureInt64 ChildrenMajorFaultsMeasure() const;
  ::opencensus::stats::MeasureInt64 UTimeMeasure() const;
  ::opencensus::stats::MeasureInt64 STimeMeasure() const;
  ::opencensus::stats::MeasureInt64 CUTimeMeasure() const;
  ::opencensus::stats::MeasureInt64 CSTimeMeasure() const;
  ::opencensus::stats::MeasureInt64 StartTimeMeasure() const;
  ::opencensus::stats::MeasureInt64 VSizeMeasure() const;
  ::opencensus::stats::MeasureInt64 RssMeasure() const;
  ::opencensus::stats::MeasureInt64 RssSLimMeasure() const;
  ::opencensus::stats::MeasureInt64 GuestTimeMeasure() const;
  ::opencensus::stats::MeasureInt64 ChildrenGuestTimeMeasure() const;

  // Measure view registration
  void RegisterView(::opencensus::stats::ViewDescriptor *view_descriptor,
                    const absl::string_view measure_name,
                    const absl::string_view measure_description);

  void RegisterMinorFaultsView();
  void RegisterChildrenMinorFaultsView();
  void RegisterMajorFaultsView();
  void RegisterChildrenMajorFaultsView();
  void RegisterUTimeView();
  void RegisterSTimeView();
  void RegisterCUTimeView();
  void RegisterCSTimeView();
  void RegisterStartTimeView();
  void RegisterVSizeView();
  void RegisterRssView();
  void RegisterRssSLimView();
  void RegisterGuestTimeView();
  void RegisterChildrenGuestTimeView();

  // Record metrics
  typedef void (OpenCensusClient::*Recorder)(const ProcStatResponse &) const;
  void RecordMinorFaults(const ProcStatResponse &response) const;
  void RecordChildrenMinorFaults(const ProcStatResponse &response) const;
  void RecordMajorFaults(const ProcStatResponse &response) const;
  void RecordChildrenMajorFaults(const ProcStatResponse &response) const;
  void RecordUTime(const ProcStatResponse &response) const;
  void RecordSTime(const ProcStatResponse &response) const;
  void RecordCUTime(const ProcStatResponse &response) const;
  void RecordCSTime(const ProcStatResponse &response) const;
  void RecordStartTime(const ProcStatResponse &response) const;
  void RecordVSize(const ProcStatResponse &response) const;
  void RecordRss(const ProcStatResponse &response) const;
  void RecordRssSLim(const ProcStatResponse &response) const;
  void RecordGuestTime(const ProcStatResponse &response) const;
  void RecordChildrenGuestTime(const ProcStatResponse &response) const;

  // Measure names
  const absl::string_view kMinorFaultsMeasureName = "proc/stat/minflt";
  const absl::string_view kChildrenMinorFaultsMeasureName = "proc/stat/cminflt";
  const absl::string_view kMajorFaultsMeasureName = "proc/stat/majflt";
  const absl::string_view kChildrenMajorFaultsMeasureName = "proc/stat/cmajflt";
  const absl::string_view kUTimeMeasureName = "proc/stat/utime";
  const absl::string_view kSTimeMeasureName = "proc/stat/stime";
  const absl::string_view kCUTimeMeasureName = "proc/stat/cutime";
  const absl::string_view kCSTimeMeasureName = "proc/stat/cstime";
  const absl::string_view kStartTimeMeasureName = "proc/stat/startime";
  const absl::string_view kVSizeMeasureName = "proc/stat/vsize";
  const absl::string_view kRssMeasureName = "proc/stat/rss";
  const absl::string_view kRssSLimMeasureName = "proc/stat/rsslim";
  const absl::string_view kGuestTimeMeasureName = "proc/stat/guesttime";
  const absl::string_view kChildrenGuestTimeMeasureName =
      "proc/stat/cguesttime";

  // Measure descriptions
  const absl::string_view kMinorFaultsMeasureDescription =
      "The number of minor faults the process has made.";
  const absl::string_view kChildrenMinorFaultsMeasureDescription =
      "The number of minor faults that any of the process's waited-for children"
      "have made.";
  const absl::string_view kMajorFaultsMeasureDescription =
      "The number of major faults the process has made.";
  const absl::string_view kChildrenMajorFaultsMeasureDescription =
      "The number of major faults that any of the process's waited-for children"
      "have made.";
  const absl::string_view kUTimeMeasureDescription =
      "Amount of time that the process has been scheduled in user mode."
      " Reported in clock ticks.";
  const absl::string_view kSTimeMeasureDescription =
      "Amount of time that the process has been scheduled in kernel mode."
      " Reported in clock ticks.";
  const absl::string_view kCUTimeMeasureDescription =
      "Amount of time that the process' waited-for children have been"
      " scheduled in user mode. Reported in clock ticks.";
  const absl::string_view kCSTimeMeasureDescription =
      "Amount of time that this process' waited-for children have been"
      " scheduled in kernel mode. Reported in clock ticks.";
  const absl::string_view kStartTimeMeasureDescription =
      "The time the process started after system boot."
      " Expressed in clock ticks.";
  const absl::string_view kVSizeMeasureDescription =
      "Virtual memory size in bytes.";
  const absl::string_view kRssMeasureDescription =
      "Number of pages the process has in real memory.";
  const absl::string_view kRssSLimMeasureDescription =
      "Current soft limit in bytes on the rss of the process.";
  const absl::string_view kGuestTimeMeasureDescription =
      "Guest time of the process. Reported in clock ticks.";
  const absl::string_view kChildrenGuestTimeMeasureDescription =
      "Guest time of the process' children. Reported in clock ticks.";

  // View descriptors
  ::opencensus::stats::ViewDescriptor minor_faults_view_descriptor_;
  ::opencensus::stats::ViewDescriptor children_minor_faults_view_descriptor_;
  ::opencensus::stats::ViewDescriptor major_faults_view_descriptor_;
  ::opencensus::stats::ViewDescriptor children_major_faults_view_descriptor_;
  ::opencensus::stats::ViewDescriptor utime_view_descriptor_;
  ::opencensus::stats::ViewDescriptor stime_view_descriptor_;
  ::opencensus::stats::ViewDescriptor cutime_view_descriptor_;
  ::opencensus::stats::ViewDescriptor cstime_view_descriptor_;
  ::opencensus::stats::ViewDescriptor start_time_view_descriptor_;
  ::opencensus::stats::ViewDescriptor vsize_view_descriptor_;
  ::opencensus::stats::ViewDescriptor rss_view_descriptor_;
  ::opencensus::stats::ViewDescriptor rss_slim_view_descriptor_;
  ::opencensus::stats::ViewDescriptor guest_time_view_descriptor_;
  ::opencensus::stats::ViewDescriptor children_guest_time_view_descriptor_;

  // ProcSystemServiceClient for gathering metrics.
  const std::unique_ptr<ProcSystemServiceClient> proc_client_;

  const OpenCensusClientConfig config_;

  // record_ is the on-off switch between the main thread and the
  // census_thread_.
  MutexGuarded<bool> record_ = MutexGuarded<bool>(false);

  // When started by StartCensus will loop iteratively through all Recorder
  // functions to record metrics.
  std::unique_ptr<Thread> census_thread_ = nullptr;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_OPENCENSUS_CLIENT_H_
