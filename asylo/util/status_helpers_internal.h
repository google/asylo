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

#ifndef ASYLO_UTIL_STATUS_HELPERS_INTERNAL_H_
#define ASYLO_UTIL_STATUS_HELPERS_INTERNAL_H_

#include <string>
#include <type_traits>

#include "google/protobuf/any.pb.h"
#include <google/protobuf/message.h>
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/types/optional.h"
#include "asylo/util/status.h"

namespace asylo {
namespace internal {

// An implementation struct for ConvertStatus(). Each specialization must have a
// method with the signature:
//
//     static ToStatusT Convert(const FromStatusT &from_status);
template <typename ToStatusT, typename FromStatusT>
struct ConvertStatusImpl;

// A specialization for converting to asylo::Status.
template <typename FromStatusT>
struct ConvertStatusImpl<Status, FromStatusT> {
  static Status Convert(const FromStatusT &from_status) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    return Status(from_status);
#pragma GCC diagnostic pop
  }
};

// A specialization for converting to absl::Status.
template <typename FromStatusT>
struct ConvertStatusImpl<absl::Status, FromStatusT> {
  static absl::Status Convert(const FromStatusT &from_status) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    // Use operator absl::Status().
    return Status(from_status);
#pragma GCC diagnostic pop
  }
};

// Most generic specialization.
template <typename ToStatusT, typename FromStatusT>
struct ConvertStatusImpl {
  static ToStatusT Convert(const FromStatusT &from_status) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    return Status(from_status).ToOtherStatus<ToStatusT>();
#pragma GCC diagnostic pop
  }
};

template <typename MessageT, typename StatusT = Status>
struct ProtoPayloadImpl {
  static_assert(std::is_base_of<google::protobuf::Message, MessageT>::value,
                "MessageT must be a protobuf message type");
  static_assert(std::is_same<StatusT, Status>::value ||
                    std::is_same<StatusT, absl::Status>::value,
                "StatusT must either be ::asylo::Status or ::absl::Status");

  static std::string GetTypeUrl() {
    google::protobuf::Any any;
    any.PackFrom(MessageT());
    return std::string(any.type_url());
  }

  static absl::optional<MessageT> GetPayload(const StatusT &status) {
    absl::optional<absl::Cord> payload = status.GetPayload(GetTypeUrl());
    if (!payload.has_value()) {
      return absl::nullopt;
    }
    MessageT message;
    if (!message.ParseFromString(std::string(payload.value()))) {
      return absl::nullopt;
    }
    return message;
  }

  static void SetPayload(const MessageT &message, StatusT &status) {
    status.SetPayload(GetTypeUrl(), absl::Cord(message.SerializeAsString()));
  }
};

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_UTIL_STATUS_HELPERS_INTERNAL_H_
