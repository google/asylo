/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/platform/primitives/remote/grpc_client_impl.h"

#include <cstdint>
#include <iterator>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/grpc_service.grpc.pb.h"
#include "asylo/platform/primitives/remote/grpc_service.pb.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/support/status.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {
namespace primitives {

namespace {

void SerializeIntoRequest(CommunicationMessage *request,
                          Communicator::Invocation *invocation) {
  *request->mutable_status() =
      StatusToProto(Status{absl::StatusCode::kUnknown, "Invocation request"});
  request->set_invocation_thread_id(invocation->invocation_thread_id);
  request->set_selector(invocation->selector);
  // Parameters are OK, serialize them into request.
  invocation->writer.Serialize([request](Extent extent) {
    auto item = request->add_items();
    if (!extent.empty()) {
      item->assign(reinterpret_cast<const char *>(extent.data()),
                   extent.size());
    }
  });
}

void DeserializeFromReply(const CommunicationMessage &reply,
                          Communicator::Invocation *invocation) {
  if (reply.has_status()) {
    invocation->status = StatusFromProto(reply.status());
    return;
  }

  // Derialize results from response.
  invocation->reader.Deserialize(reply.items_size(), [&reply](size_t i) {
    const auto &item = reply.items(i);
    return Extent{item.data(), item.size()};
  });
}

}  // namespace

Status Communicator::ClientImpl::RunInvocation(
    Communicator::Invocation *invocation) {
  if (!communicator_->is_client_ready_.load()) {
    return Status{absl::StatusCode::kCancelled, "Disconnected"};
  }

  // Prepare request sequence number to make certain response matches
  // the request.
  const auto request_sequence_number = GenerateSequenceNumber();

  // Send request to the counterpart.
  {
    CommunicationMessage request;
    SerializeIntoRequest(&request, invocation);
    request.set_request_sequence_number(request_sequence_number);
    ASYLO_RETURN_IF_ERROR(SendCommunication(request));
  }

  // Loop until response is received, in a mean time processing requests on the
  // same thread.
  {
    CommunicationMessagePtr wrapped_message;
    ASYLO_ASSIGN_OR_RETURN(wrapped_message, communicator_->MessageLoop());

    // Verify sequence number match.
    if (wrapped_message->request_sequence_number() != request_sequence_number) {
      return Status{absl::StatusCode::kInternal,
                    "Response sequence number does not match request"};
    }

    // Response received, store it.
    DeserializeFromReply(*wrapped_message, invocation);
  }

  return invocation->status;
}

Communicator::ClientImpl::~ClientImpl() = default;
Communicator::ClientImpl::ClientImpl(Communicator *communicator)
    : sequence_number_(0), communicator_(CHECK_NOTNULL(communicator)) {}

StatusOr<std::unique_ptr<Communicator::ClientImpl>>
Communicator::ClientImpl::Create(const RemoteProxyConfig &config,
                                 absl::string_view remote_address,
                                 Communicator *communicator) {
  std::unique_ptr<ClientImpl> client(new ClientImpl(communicator));
  client->grpc_channel_ = ::grpc::CreateCustomChannel(
      std::string(remote_address), config.channel_creds(),
      config.channel_args());
  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(10, GPR_TIMESPAN));
  if (!client->grpc_channel_->WaitForConnected(absolute_deadline)) {
    return Status(absl::StatusCode::kDeadlineExceeded, "Failed to connect");
  }
  client->grpc_stub_ =
      CommunicatorService::NewStub(client->grpc_channel_);

  if (communicator->is_host()) {
    const RemoteProxyClientConfig &client_config =
        dynamic_cast<const RemoteProxyClientConfig &>(config);
    StatusOr<OpenCensusClientConfig> config_result =
        client_config.GetOpenCensusMetricsConfig();
    if (config_result.ok()) {
      client->open_census_client_ = OpenCensusClient::Create(
          client->grpc_channel_, config_result.value());
    }
  }

  return std::move(client);
}

Status Communicator::ClientImpl::SendCommunication(
    const CommunicationMessage &message) {
  ASYLO_RETURN_IF_ERROR(IsMessageValid(message));
  CommunicationConfirmation confirmation;
  if (communicator_->is_host()) {
    confirmation.set_host_time_nanos(absl::GetCurrentTimeNanos());
  }
  ::grpc::ClientContext context;
  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(5, GPR_TIMESPAN));
  context.set_deadline(absolute_deadline);
  auto grpc_status = grpc_stub_->Communicate(&context, message, &confirmation);
  if (!grpc_status.ok()) {
    return Status{absl::StatusCode::kInternal,
                  absl::StrCat("gRPC ErrorCode=", grpc_status.error_code(),
                               ", ErrorMessage=", grpc_status.error_message())};
  }
  // If host responded with time stamp, process it.
  if (!communicator_->is_host() && confirmation.has_host_time_nanos()) {
    communicator_->set_host_time_nanos(confirmation.host_time_nanos());
  }

  return absl::OkStatus();
}

void Communicator::ClientImpl::SendDisconnect() {
  DisconnectRequest request;
  DisconnectReply reply;
  ::grpc::ClientContext context;
  // Do not set deadline - Disconnect may take an arbitrarily long time.
  const auto grpc_status = grpc_stub_->Disconnect(&context, request, &reply);
  if (!grpc_status.ok()) {
    LOG(ERROR) << "SendDisconnect error="
               << ConvertStatus<absl::Status>(grpc_status);
  }
}

void Communicator::ClientImpl::SendEndPointAddress(absl::string_view address) {
  EndPointAddressNotification request;
  request.set_address(address.data(), address.size());
  EndPointAddressReply reply;
  ::grpc::ClientContext context;
  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(5, GPR_TIMESPAN));
  context.set_deadline(absolute_deadline);
  const auto grpc_status =
      grpc_stub_->EndPointAddress(&context, request, &reply);
  if (!grpc_status.ok()) {
    LOG(ERROR) << "SendEndPointAddress error="
               << ConvertStatus<absl::Status>(grpc_status);
  }
}

void Communicator::ClientImpl::SendDisposeOfThread(
    Thread::Id exiting_thread_id) {
  DisposeOfThreadRequest request;
  request.set_exiting_thread_id(exiting_thread_id);
  DisposeOfThreadReply reply;
  ::grpc::ClientContext context;
  // Do not set deadline - DisposeOfThread may take an arbitrarily long time.
  const auto grpc_status =
      grpc_stub_->DisposeOfThread(&context, request, &reply);
  if (!grpc_status.ok()) {
    LOG(ERROR) << "SendDisposeOfThread error="
               << ConvertStatus<absl::Status>(grpc_status);
  }
}

uint64_t Communicator::ClientImpl::GenerateSequenceNumber() {
  return sequence_number_.fetch_add(1, std::memory_order_seq_cst);
}

}  // namespace primitives
}  // namespace asylo
