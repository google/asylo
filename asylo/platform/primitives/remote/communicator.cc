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

#include "asylo/platform/primitives/remote/communicator.h"

#include <cstdint>
#include <memory>
#include <queue>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/util/logging.h"
#include "include/grpcpp/support/status.h"
#include "asylo/platform/primitives/remote/grpc_client_impl.h"
#include "asylo/platform/primitives/remote/grpc_server_impl.h"
#include "asylo/platform/primitives/remote/grpc_service.grpc.pb.h"
#include "asylo/platform/primitives/remote/grpc_service.pb.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {
namespace primitives {

ABSL_CONST_INIT thread_local Communicator::ThreadActivityWorkQueue
    *Communicator::current_thread_context_ = nullptr;

thread_local std::unique_ptr<Cleanup> Communicator::thread_exiter_;

MutexGuarded<absl::flat_hash_set<Communicator *>>
    *Communicator::active_communicators() {
  static const auto static_active_communicators =
      new MutexGuarded<absl::flat_hash_set<Communicator *>>(
          absl::flat_hash_set<Communicator *>());
  return static_active_communicators;
}

// Encapsulates the necessary information to schedule multiple messages for
// processing on the same worker thread. Created when host_thread_id shows up
// for the first time on 'Communicate' RPC.
class Communicator::ThreadActivityWorkQueue {
 public:
  // Pushes a message to be processed in the context of this thread.
  Status QueueMessage(CommunicationMessagePtr wrapped_message) {
    wrapped_messages_queue_.Lock()->queue.emplace(std::move(wrapped_message));
    return absl::OkStatus();
  }

  // Runs a loop getting messages and processing requests until response is
  // received (returns it) or thread is signaled to exit (returns status).
  StatusOr<CommunicationMessagePtr> MessageLoop(Communicator *communicator) {
    for (;;) {
      CommunicationMessagePtr wrapped_message;
      {
        auto locked_message_queue = wrapped_messages_queue_.LockWhen(
            [](const WrappedMessageQueue &message_queue) {
              return message_queue.is_exiting || !message_queue.queue.empty();
            });
        if (locked_message_queue->is_exiting) {
          return Status(absl::StatusCode::kCancelled, "Channel disconnected");
        }
        wrapped_message = std::move(locked_message_queue->queue.front());
        locked_message_queue->queue.pop();
      }
      // A message was received, it must have a selector and thread id.
      Status message_status = IsMessageValid(*wrapped_message);
      if (!message_status.ok()) {
        LOG(ERROR) << "Malformed message ignored, status=" << message_status;
        continue;
      }
      if (wrapped_message->has_status()) {
        message_status = StatusFromProto(wrapped_message->status());
      }
      if (message_status.code() != absl::StatusCode::kUnknown) {
        // Response received.
        return std::move(wrapped_message);
      }
      // Construct server-side invocation from wrapped message.
      communicator->service_->StartInvocation(std::move(wrapped_message));
      // Wrapped message is now discarded, triggering service to confirm
      // delivery to the counterpart Communicator.
    }
  }

  void SetWorkerThread(std::unique_ptr<Thread> new_worker) {
    worker_thread_ = std::move(new_worker);
    CHECK(worker_thread_);
  }

  Thread::Id GetHostThreadId() const { return host_thread_id_; }

  void SignalExit() { wrapped_messages_queue_.Lock()->is_exiting = true; }

  explicit ThreadActivityWorkQueue(Thread::Id host_thread_id)
      : wrapped_messages_queue_(WrappedMessageQueue()),
        host_thread_id_(host_thread_id) {}

  ~ThreadActivityWorkQueue() {
    SignalExit();
    if (worker_thread_) {
      worker_thread_->Join();
      worker_thread_.reset();
    }
    auto locked_message_queue = wrapped_messages_queue_.ReaderLock();
    CHECK(locked_message_queue->is_exiting ||
          locked_message_queue->queue.empty());
  }

  ThreadActivityWorkQueue(const ThreadActivityWorkQueue &other) = delete;
  ThreadActivityWorkQueue &operator=(const ThreadActivityWorkQueue &other) =
      delete;

  // Static map of per-thread activity thread contexts: each participating
  // thread is added when the thread first shows up on Communicator. Keyed by
  // the thread id which made the outermost Invoke call. While processing that
  // call, nested Invokes could have been sent by this Communicator or its
  // counterpart with an expectation that they will be handled by the same
  // thread on each side. 'invocation_thread_id' is passed with every Invoke RPC
  // request and allows Communicator to assign the handling to the matching
  // worker thread.
  static MutexGuarded<
      absl::flat_hash_map<Thread::Id, std::unique_ptr<ThreadActivityWorkQueue>>>
      *map() {
    static const auto static_map = new MutexGuarded<absl::flat_hash_map<
        Thread::Id, std::unique_ptr<ThreadActivityWorkQueue>>>(
        absl::flat_hash_map<Thread::Id,
                            std::unique_ptr<ThreadActivityWorkQueue>>());
    return static_map;
  }

 private:
  // Guarded 'wrapped_messages_queue_' owned by this context.
  // Thread controlled by ThreadActivityWorkQueue ('worker_thread' for the
  // target, application thread for the host) is either processing a message
  // retrieved from the queue, or blocked on this mutex waiting for more
  // message(s) to arrive.
  struct WrappedMessageQueue {
    // Queue of messages to be processed on the thread. When the queue is empty,
    // the MessageLoop method will wait for messages to be enqueued.
    // Each message represents either an Invocation request that the counterpart
    // Communicator sent for processing on this thread, or the response from the
    // other side to an Invocation that this Communicator's thread sent.
    std::queue<CommunicationMessagePtr> queue;

    // Flag inidicating that the thread needs to exit.
    bool is_exiting = false;
  };
  MutexGuarded<WrappedMessageQueue> wrapped_messages_queue_;

  // Host thread id (for host side it matches the current thread).
  const Thread::Id host_thread_id_;

  // On target: thread that processes requests coming from invocation_thread_id.
  // On host: nullptr (requests, if any, are processed by the application
  // thread).
  std::unique_ptr<Thread> worker_thread_;
};

StatusOr<Communicator::ThreadActivityWorkQueue *>
Communicator::LocateOrCreateThreadActivityWorkQueue(
    Thread::Id invocation_thread_id) {
  auto locked_threads_map = ThreadActivityWorkQueue::map()->Lock();
  auto it = locked_threads_map->find(invocation_thread_id);
  if (it == locked_threads_map->end()) {
    auto ins = locked_threads_map->emplace(
        invocation_thread_id,
        absl::make_unique<ThreadActivityWorkQueue>(invocation_thread_id));
    if (!ins.second) {
      return Status(absl::StatusCode::kInternal,
                    "Failed to add thread to the map");
    }
    it = ins.first;
    if (is_host()) {
      // Before recording current_thread_context_, set a thread exit callback
      // which will signal the target side that the matching thread is no longer
      // needed. This callback will be invoked on that host thread when it is
      // exiting.
      thread_exiter_ = absl::make_unique<Cleanup>([invocation_thread_id]() {
        for (auto communicator : *active_communicators()->ReaderLock()) {
          if (communicator->IsConnected()) {
            communicator->client_->SendDisposeOfThread(invocation_thread_id);
          }
        }
      });
    } else {
      // Create new thread to handle requests associated with that thread_id.
      // On a host side we are always called by that very thread (when we first
      // send something from it).
      auto *const thread_activity_context = it->second.get();
      auto new_worker =
          absl::make_unique<Thread>([this, thread_activity_context] {
            CHECK(!current_thread_context_);
            current_thread_context_ = thread_activity_context;
            auto message_result = MessageLoop();
            current_thread_context_ = nullptr;
            // May not end receiving a message.
            CHECK(!message_result.ok())
                << "Received a message that is not a request, ignored:"
                << message_result.status();
          });
      if (!new_worker) {
        locked_threads_map->erase(it);
        return Status(absl::StatusCode::kResourceExhausted,
                      "Failed to start worker thread to handle requests");
      }
      it->second->SetWorkerThread(std::move(new_worker));
    }
  }
  return it->second.get();
}

StatusOr<Communicator::CommunicationMessagePtr> Communicator::MessageLoop() {
  return current_thread_context_->MessageLoop(this);
}

void Communicator::QueueMessageForThread(
    CommunicationMessagePtr wrapped_message) {
  Status message_status = IsMessageValid(*wrapped_message);
  if (!message_status.ok()) {
    LOG(ERROR) << "Malformed InvocationParameters message, status="
               << message_status;
    return;
  }
  const Thread::Id invocation_thread_id =
      wrapped_message->invocation_thread_id();

  if (is_host()) {
    CHECK_NE(invocation_thread_id, Thread::this_thread_id())
        << "Cannot assign action to the current thread";
  }
  const auto thread_context_result =
      LocateOrCreateThreadActivityWorkQueue(invocation_thread_id);
  ASYLO_CHECK_OK(thread_context_result.status());
  thread_context_result.value()->QueueMessage(std::move(wrapped_message));
}

Status Communicator::CreateStub(const RemoteProxyConfig &config,
                                absl::string_view remote_address) {
  ASYLO_ASSIGN_OR_RETURN(client_,
                         ClientImpl::Create(config, remote_address, this));
  return absl::OkStatus();
}

Status Communicator::StartServer(
    const std::shared_ptr<::grpc::ServerCredentials> &server_creds,
    int requested_port) {
  // Create gRPC server and start listening.
  if (service_) {
    return Status(absl::StatusCode::kAlreadyExists, "Server already created.");
  }
  ASYLO_ASSIGN_OR_RETURN(
      service_, ServiceImpl::Create(requested_port, server_creds, this));
  // Success.
  is_server_ready_.store(true);
  return absl::OkStatus();
}

void Communicator::ServerRpcLoop() {
  service_->ServerRpcLoop();
  CHECK(!current_thread_context_) << "RPC thread does not process Invocations";
}

Status Communicator::Connect(const RemoteProxyConfig &config,
                             absl::string_view remote_address) {
  // Create gRPC stub for writing.
  ASYLO_RETURN_IF_ERROR(CreateStub(config, remote_address));
  // Success.
  is_client_ready_.store(true);
  return absl::OkStatus();
}

Communicator::Communicator(bool is_host)
    : is_host_(is_host),
      is_server_ready_(false),
      is_client_ready_(false),
      last_host_time_nanos_(absl::nullopt) {
  if (is_host) {
    // For host: register communicator in the static set.
    CHECK(active_communicators()->Lock()->emplace(this).second);
  }
}

Communicator::~Communicator() {
  Disconnect();
  if (is_host()) {
    // For host: unregister communicator from the static set.
    auto locked_active_communicators = active_communicators()->Lock();
    CHECK_EQ(locked_active_communicators->erase(this), 1);
    if (!locked_active_communicators->empty()) {
      // More active communicators remained, bail out.
      return;
    }
  }
  // For target Communicator or the last active Communicator in host: signal
  // created threads that they need to stop (when thread contexts are
  // destructed on target, they will wait for stoppage to occur).
  ThreadActivityWorkQueue::map()->Release().clear();
}

void Communicator::set_handler(
    std::function<void(std::unique_ptr<Invocation> invocation)> handler) {
  service_->set_handler(std::move(handler));
}

void Communicator::SendEndPointAddress(absl::string_view address) {
  client_->SendEndPointAddress(address);
}

std::string Communicator::WaitForEndPointAddress() {
  return service_->WaitForEndPointAddress();
}

void Communicator::Disconnect() {
  if (is_client_ready_.exchange(false)) {
    client_->SendDisconnect();
  }
  if (is_server_ready_.exchange(false)) {
    service_->WaitForDisconnect();
  }
}

void Communicator::DisposeOfThread(Thread::Id exiting_thread_id) {
  CHECK(!is_host());
  std::unique_ptr<ThreadActivityWorkQueue> thread_context;
  {
    auto locked_threads_map = ThreadActivityWorkQueue::map()->Lock();
    auto it = locked_threads_map->find(exiting_thread_id);
    if (it == locked_threads_map->end()) {
      return;
    }
    thread_context = std::move(it->second);
    locked_threads_map->erase(it);
  }
  if (thread_context) {
    thread_context->SignalExit();
  }
}

bool Communicator::IsConnected() const {
  return is_server_ready_.load() && is_client_ready_.load();
}

void Communicator::Invoke(
    uint64_t selector,
    const std::function<void(Invocation *invocation)> &params_setter,
    std::function<void(std::unique_ptr<Invocation> invocation)> callback) {
  const auto prior_context = current_thread_context_;
  auto invocation = absl::make_unique<Invocation>();
  // Always return with the callback, and restore current_thread_context_.
  asylo::Cleanup cleanup([&callback, &invocation, prior_context] {
    callback(std::move(invocation));
    current_thread_context_ = prior_context;
  });

  // Locate thread context.
  const auto thread_id = Thread::this_thread_id();
  if (is_host() && !current_thread_context_) {
    // On host side use current thread id to locate thread context.
    const auto thread_context_result =
        LocateOrCreateThreadActivityWorkQueue(thread_id);
    if (!thread_context_result.ok()) {
      invocation->status = thread_context_result.status();
      return;
    }
    current_thread_context_ = thread_context_result.value();
  }
  if (!current_thread_context_) {
    invocation->status = Status{
        absl::StatusCode::kInternal,
        absl::StrCat("Thread has no cached context, thread_id=", thread_id,
                     ", is_host=", is_host())};
    return;
  }

  // Fill in invocation.
  invocation->selector = selector;
  invocation->invocation_thread_id = current_thread_context_->GetHostThreadId();
  params_setter(invocation.get());
  if (!invocation->status.ok()) {
    return;
  }
  invocation->status = client_->RunInvocation(invocation.get());
}

Status Communicator::SendCommunication(const CommunicationMessage &message) {
  return client_->SendCommunication(message);
}

int Communicator::server_port() const { return service_->server_port(); }

Status Communicator::IsMessageValid(const CommunicationMessage &message) {
  if (!message.has_request_sequence_number()) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  "Message has no request_sequence_number"};
  }
  if (!message.has_invocation_thread_id()) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  "Message has no invocation_thread_id"};
  }
  if (!message.has_selector()) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  "Message has no selector"};
  }
  return absl::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
