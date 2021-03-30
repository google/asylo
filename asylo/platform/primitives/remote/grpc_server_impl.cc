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

#include "asylo/platform/primitives/remote/grpc_server_impl.h"

#include <atomic>
#include <cstdint>
#include <ctime>
#include <iterator>
#include <string>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/remote/grpc_service.grpc.pb.h"
#include "asylo/platform/primitives/remote/grpc_service.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_service.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpc/impl/codegen/gpr_types.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/impl/codegen/completion_queue.h"
#include "include/grpcpp/support/status.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/impl/codegen/async_unary_call.h"
#include "include/grpcpp/impl/codegen/server_context.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"

ABSL_FLAG(
    int64_t, host_time_expiration_ms, 500,
    "For target side only: number of milliseconds the timestamp is to be used "
    "after it has been received from the host communicator");

namespace asylo {
namespace primitives {

namespace {

class ServerInvocation : public Communicator::Invocation {
 public:
  ServerInvocation(
      const CommunicationMessage &request,
      std::function<void(const CommunicationMessage &response)> send_response)
      : send_response_(CHECK_NOTNULL(std::move(send_response))) {
    DeserializeFromRequest(request);
  }

  ~ServerInvocation() override {
    // Serialize into response.
    CommunicationMessage response;
    if (status.code() == absl::StatusCode::kUnknown) {
      // UNKNOWN status indicates request, cannot be returned with response.
      status = Status{
          absl::StatusCode::kFailedPrecondition,
          absl::StrCat("Unacceptable status returned ", status.ToString())};
    }
    SerializeIntoResponse(&response);
    // Send response back.
    send_response_(response);
  }

 private:
  void DeserializeFromRequest(const CommunicationMessage &request) {
    request_sequence_number_ = request.request_sequence_number();
    selector = request.selector();
    invocation_thread_id = request.invocation_thread_id();
    reader.Deserialize(request.items_size(), [&request](size_t i) {
      auto const &item = request.items(i);
      return Extent{item.data(), item.size()};
    });
  }

  void SerializeIntoResponse(CommunicationMessage *response) const {
    response->set_request_sequence_number(
        request_sequence_number_);  // copy request quid for coherence check
    response->set_selector(selector);
    response->set_invocation_thread_id(invocation_thread_id);
    if (!status.ok()) {
      *response->mutable_status() = StatusToProto(status);
    } else {
      writer.Serialize([response](Extent extent) {
        auto item = response->add_items();
        if (!extent.empty()) {
          item->assign(reinterpret_cast<const char *>(extent.data()),
                       extent.size());
        }
      });
    }
  }

  uint64_t request_sequence_number_;
  const std::function<void(const CommunicationMessage &response)>
      send_response_;
};

}  // namespace

void Communicator::ServiceImpl::StartInvocation(
    CommunicationMessagePtr wrapped_message) {
  auto invocation = absl::make_unique<ServerInvocation>(
      *wrapped_message, [this](const CommunicationMessage &response) {
        const Status send_status = communicator_->SendCommunication(response);
        LOG_IF(ERROR, !send_status.ok())
            << "Failed to send response, status=" << send_status;
      });
  // The request message has been deserialized, drop it letting the RPC finish
  // and send confirmation to the caller.
  wrapped_message.reset();
  // Call service-side handler handing invocation to it.
  // Note that wrapper message has already been destructed.
  if (!handler_) {
    invocation->status = Status{absl::StatusCode::kFailedPrecondition,
                                "Invocation handler not set"};
    return;
  }
  handler_(std::move(invocation));
}

// Server-side instance base that asynchronously processes one RPC call through
// its stages.
class Communicator::ServiceImpl::RpcInstance {
 public:
  explicit RpcInstance(Communicator::ServiceImpl *service)
      : service_(CHECK_NOTNULL(service)), completed_(false) {}
  virtual ~RpcInstance() = default;

  RpcInstance(const RpcInstance &other) = delete;
  RpcInstance &operator=(const RpcInstance &other) = delete;

  // Invoked when the processing is completed (once and only once).
  void Complete() {
    CHECK(!completed_);
    completed_ = true;
    RespondRpc();
  }

  void ProcessRpc(bool ok) {
    if (!ok || completed_) {
      // Once failed or completed, deallocate ourselves (RpcInstance).
      delete this;
      return;
    }
    ExecuteRpc();
  }

  Communicator::ServiceImpl *service() const { return service_; }
  ::grpc::ServerCompletionQueue *completion_queue() const {
    return service_->completion_queue_.get();
  }
  ::grpc::ServerContext *context() { return &context_; }

 private:
  // Executes specific RPC.
  virtual void ExecuteRpc() = 0;

  // Responds to RPC.
  virtual void RespondRpc() = 0;

  // The means of communication with the gRPC runtime for an asynchronous
  // server.
  Communicator::ServiceImpl *const service_;

  // Context for the rpc, allowing to tweak aspects of it such as the use
  // of compression, authentication, as well as to send metadata back to the
  // client.
  ::grpc::ServerContext context_;

  // Can only be destructed once completed_ is true.
  bool completed_;  // The current serving state.
};

class Communicator::ServiceImpl::CommunicationRpcInstance
    : public Communicator::ServiceImpl::RpcInstance {
 public:
  // Take in the "service" instance (in this case representing an asynchronous
  // server) and the "completion_queue" used for asynchronous communication
  // with the gRPC runtime.
  explicit CommunicationRpcInstance(Communicator::ServiceImpl *service)
      : Communicator::ServiceImpl::RpcInstance(service), responder_(context()) {
    // Request* that the system start processing Send requests. In this request,
    // "this" acts as the tag uniquely identifying the request (so that
    // different InvokeRpcInstance instances can serve different requests
    // concurrently), in this case the memory address of this InvokeRpcInstance.
    service->RequestCommunicate(context(), &message_, &responder_,
                                completion_queue(), completion_queue(), this);
  }

 private:
  void RespondRpc() override {
    // If host responds to the target, add time stamp.
    if (service()->communicator_->is_host()) {
      confirmation_.set_host_time_nanos(absl::GetCurrentTimeNanos());
    }

    // And we are done! Let the gRPC runtime know we've finished, using the
    // memory address of this instance as the uniquely identifying tag for
    // the event.
    responder_.Finish(confirmation_, ::grpc::Status::OK, this);
  }

  void ExecuteRpc() override {
    // Spawn a new CommunicationRpcInstance instance to serve new clients while
    // we process the one for this InvokeRpcInstance. The instance will
    // deallocate itself once completed.
    new CommunicationRpcInstance(service());

    // If received time stamp from host with request, store it.
    if (!service()->communicator_->is_host() &&
        message_.has_host_time_nanos()) {
      service()->communicator_->set_host_time_nanos(message_.host_time_nanos());
    }

    service()->communicator_->QueueMessageForThread(CommunicationMessagePtr(
        &message_, WrappedMessageDeleter([this] { Complete(); })));
  }

  // What we get from the client.
  CommunicationMessage message_;

  // What we send back to the client.
  CommunicationConfirmation confirmation_;

  // The means to get back to the client (must always be the last: destruct
  // it before message_ and confirmation_).
  ::grpc::ServerAsyncResponseWriter<CommunicationConfirmation> responder_;
};

class Communicator::ServiceImpl::DisconnectRpcInstance
    : public Communicator::ServiceImpl::RpcInstance {
 public:
  // Take in the "service" instance (in this case representing an asynchronous
  // server) and the "completion_queue" used for asynchronous communication
  // with the gRPC runtime.
  explicit DisconnectRpcInstance(Communicator::ServiceImpl *service)
      : Communicator::ServiceImpl::RpcInstance(service), responder_(context()) {
    // Request* that the system start processing Send requests. In this request,
    // "this" acts as the tag uniquely identifying the request (so that
    // different DisconnectRpcInstance instances can serve different requests
    // concurrently), in this case the memory address of this
    // DisconnectRpcInstance.
    service->RequestDisconnect(context(), &request_, &responder_,
                               completion_queue(), completion_queue(), this);
  }

 private:
  void RespondRpc() override {
    // And we are done! Let the gRPC runtime know we've finished, using the
    // memory address of this instance as the uniquely identifying tag for
    // the event.
    responder_.Finish(confirmation_, ::grpc::Status::OK, this);
  }

  void ExecuteRpc() override {
    // Spawn a new DisconnectRpcInstance instance to serve new clients while we
    // process the one for this DisconnectRpcInstance. The instance will
    // deallocate itself once completed.
    new DisconnectRpcInstance(service());

    service()->communicator_->is_client_ready_.store(false);
    service()->communicator_->is_server_ready_.store(false);
    // Copy service() out, because after Complete() we cannot rely on 'this'
    // anymore. And we do not want to delay Complete() until after
    // WaitForDisconnect() finishes.
    const auto service_hold = service();
    Complete();
    service_hold->WaitForDisconnect();
  }

  // What we get from the client.
  DisconnectRequest request_;

  // What we send back to the client.
  DisconnectReply confirmation_;

  // The means to get back to the client (must always be the last: destruct
  // it before request_ and confirmation_).
  ::grpc::ServerAsyncResponseWriter<DisconnectReply> responder_;
};

class Communicator::ServiceImpl::DisposeOfThreadRpcInstance
    : public Communicator::ServiceImpl::RpcInstance {
 public:
  // Take in the "service" instance (in this case representing an asynchronous
  // server) and the "completion_queue" used for asynchronous communication
  // with the gRPC runtime.
  explicit DisposeOfThreadRpcInstance(Communicator::ServiceImpl *service)
      : Communicator::ServiceImpl::RpcInstance(service), responder_(context()) {
    // Request* that the system start processing Send requests. In this request,
    // "this" acts as the tag uniquely identifying the request (so that
    // different DisposeOfThreadRpcInstance instances can serve different
    // requests concurrently), in this case the memory address of this
    // DisposeOfThreadRpcInstance.
    service->RequestDisposeOfThread(context(), &request_, &responder_,
                                    completion_queue(), completion_queue(),
                                    this);
  }

 private:
  void RespondRpc() override {
    // And we are done! Let the gRPC runtime know we've finished, using the
    // memory address of this instance as the uniquely identifying tag for
    // the event.
    responder_.Finish(confirmation_, ::grpc::Status::OK, this);
  }

  void ExecuteRpc() override {
    // Spawn a new DisposeOfThreadRpcInstance instance to serve new clients
    // while we process the one for this DisposeOfThreadRpcInstance. The
    // instance will deallocate itself once completed.
    new DisposeOfThreadRpcInstance(service());

    service()->communicator_->DisposeOfThread(request_.exiting_thread_id());
    Complete();
  }

  // What we get from the client.
  DisposeOfThreadRequest request_;

  // What we send back to the client.
  DisposeOfThreadReply confirmation_;

  // The means to get back to the client (must always be the last: destruct
  // it before request_ and confirmation_).
  ::grpc::ServerAsyncResponseWriter<DisposeOfThreadReply> responder_;
};

class Communicator::ServiceImpl::EndPointAddressRpcInstance
    : public Communicator::ServiceImpl::RpcInstance {
 public:
  // Take in the "service" instance (in this case representing an asynchronous
  // server) and the "completion_queue" used for asynchronous communication
  // with the gRPC runtime.
  explicit EndPointAddressRpcInstance(Communicator::ServiceImpl *service)
      : Communicator::ServiceImpl::RpcInstance(service), responder_(context()) {
    // Request* that the system start processing Send requests. In this request,
    // "this" acts as the tag uniquely identifying the request (so that
    // different EndPointAddressRpcInstance instances can serve different
    // requests concurrently), in this case the memory address of this
    // EndPointAddressRpcInstance.
    service->RequestEndPointAddress(context(), &request_, &responder_,
                                    completion_queue(), completion_queue(),
                                    this);
  }

 private:
  void RespondRpc() override {
    // And we are done! Let the gRPC runtime know we've finished, using the
    // memory address of this instance as the uniquely identifying tag for
    // the event.
    responder_.Finish(confirmation_, ::grpc::Status::OK, this);
  }

  void ExecuteRpc() override {
    // Spawn a new EndPointAddressRpcInstance instance to serve new clients
    // while we process the one for this EndPointAddressRpcInstance. The
    // instance will deallocate itself once completed.
    new EndPointAddressRpcInstance(service());

    service()->RecordEndPointAddress(request_.address());
    Complete();
  }

  // What we get from the client.
  EndPointAddressNotification request_;

  // What we send back to the client.
  EndPointAddressReply confirmation_;

  // The means to get back to the client (must always be the last: destruct
  // it before request_ and confirmation_).
  ::grpc::ServerAsyncResponseWriter<EndPointAddressReply> responder_;
};

StatusOr<std::unique_ptr<Communicator::ServiceImpl>>
Communicator::ServiceImpl::Create(
    int requested_port, const std::shared_ptr<::grpc::ServerCredentials> &creds,
    Communicator *communicator) {
  std::unique_ptr<ServiceImpl> service(new ServiceImpl(communicator));
  ::grpc::ServerBuilder builder;
  builder.RegisterService(service.get());
  if (!communicator->is_host()) {
    service->proc_system_service_ =
        absl::make_unique<ProcSystemServiceImpl>(getpid());
    builder.RegisterService(service->proc_system_service_.get());
  }
  builder.AddListeningPort(absl::StrCat("[::]:", requested_port), creds,
                           &service->server_port_);
  service->completion_queue_ = builder.AddCompletionQueue();
  service->server_ = builder.BuildAndStart();
  if (service->server_port_ == 0) {
    return Status(absl::StatusCode::kInternal, "Local_port not assigned");
  }
  if (requested_port != 0 && service->server_port_ != requested_port) {
    return Status(absl::StatusCode::kInternal,
                  "Local_port does not match requested_port");
  }
  if (communicator->is_host()) {
    auto raw_service = service.get();
    raw_service->rpc_thread_ = absl::make_unique<Thread>(
        [raw_service] { raw_service->ServerRpcLoop(); });
  }
  return std::move(service);
}

void Communicator::ServiceImpl::ServerRpcLoop() {
  // Spawn new RpcInstances for all possible RPCs to serve new clients.
  new CommunicationRpcInstance(this);
  new DisconnectRpcInstance(this);
  new DisposeOfThreadRpcInstance(this);
  new EndPointAddressRpcInstance(this);

  void *tag;  // uniquely identifies a request.
  bool ok;
  // Iterate and block waiting to read the next request from the completion
  // queue. The request event is uniquely identified by its tag, which is the
  // memory address of an RpcInstance.
  // The return value of Next should always be checked. This return value
  // tells us whether there is any kind of event or cq_ is shutting down.
  for (;;) {
    gpr_timespec next_deadline = gpr_time_add(
        gpr_now(GPR_CLOCK_REALTIME),
        gpr_time_from_millis(absl::GetFlag(FLAGS_host_time_expiration_ms),
                             GPR_TIMESPAN));
    const auto next_status =
        completion_queue_->AsyncNext(&tag, &ok, next_deadline);
    if (next_status == grpc::CompletionQueue::SHUTDOWN) {
      break;
    }
    if (next_status == grpc::CompletionQueue::TIMEOUT) {
      communicator_->invalidate_host_time_nanos();
      continue;
    }
    CHECK_EQ(next_status, grpc::CompletionQueue::GOT_EVENT);
    static_cast<RpcInstance *>(tag)->ProcessRpc(ok);
  }
}

Communicator::ServiceImpl::~ServiceImpl() {
  WaitForDisconnect();
  if (rpc_thread_) {
    rpc_thread_->Join();
  }
}

std::string Communicator::ServiceImpl::WaitForEndPointAddress() {
  if (address_state_.ReaderLock()->has_value() == false) {
    {
      // Wait until end_point_address_callback_ is available.
      auto end_point_address_callback_lock =
          end_point_address_callback_.LockWhen(
              [](const absl::optional<address_callback> &v) {
                return !v.has_value();
              });

      // While under lock, set callback to set the address_state_ to
      // end_point_address and exit scope.
      *end_point_address_callback_lock =
          [this](absl::string_view end_point_address) {
            *address_state_.Lock() = std::string(end_point_address);
          };
    }

    // Wait outside lock until the address_state_ has been updated with the
    // end_point_address, and take lock when it has.
    address_state_.ReaderLockWhen(
        [](const absl::optional<std::string> &v) { return v.has_value(); });

    // Reset the callback.
    end_point_address_callback_.Lock()->reset();
  }
  return std::string(address_state_.ReaderLock()->value());
}

void Communicator::ServiceImpl::WaitForDisconnect() {
  if (server_) {
    server_->Shutdown();
  }
  // Shut down completion queue after the service.
  if (completion_queue_) {
    completion_queue_->Shutdown();
  }
}

void Communicator::ServiceImpl::RecordEndPointAddress(
    absl::string_view address) {
  auto end_point_address_callback_lock =
      end_point_address_callback_.ReaderLockWhen(
          [](const absl::optional<address_callback> &v) {
            return v.has_value();
          });
  end_point_address_callback_lock->value()(address);
}

}  // namespace primitives
}  // namespace asylo
