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

#include "asylo/platform/primitives/remote/local_exit_calls.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_util.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/proxy_server.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/exit_log.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/system_call/type_conversions/generated_types.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace primitives {

namespace {

class GetTimeExitCallHandler
    : public LocalExitCallForwarder::LocalExitCallHandler {
 public:
  explicit GetTimeExitCallHandler(Communicator *communicator,
                                  LocalExitCallForwarder *forwarder)
      : LocalExitCallForwarder::LocalExitCallHandler(
            host_call::kClockGettimeHandler, forwarder),
        communicator_(communicator) {}

  absl::optional<Status> AttemptExecute(MessageReader *input,
                                        MessageWriter *output) override {
    // Filter out the calls that need to be forwarded to the proxy client.
    if (input->size() != 1 ||
        input->peek<clockid_t>() != kLinux_CLOCK_REALTIME) {
      return absl::nullopt;
    }

    // Process gettime selector locally.
    const auto host_time_nanos = communicator_->last_host_time_nanos();
    if (host_time_nanos.has_value()) {
      input->next();  // analyzed above with peek()
      constexpr int64_t kNanosecondsPerSecond = 1000000000L;
      struct timespec host_time;
      host_time.tv_sec = host_time_nanos.value() / kNanosecondsPerSecond;
      host_time.tv_nsec = host_time_nanos.value() % kNanosecondsPerSecond;
      output->Push<int32_t>(0);  // result
      output->Push<int32_t>(0);  // errno
      output->Push<struct timespec>(host_time);
      return absl::OkStatus();
    }
    // Otherwise return no-value status.
    return Status{absl::StatusCode::kNotFound,
                  "Host time not received or expired"};
  }

 private:
  Communicator *const communicator_;
};

class SysFutexWaitExitCallHandler
    : public LocalExitCallForwarder::LocalExitCallHandler {
 public:
  explicit SysFutexWaitExitCallHandler(LocalExitCallForwarder *forwarder)
      : LocalExitCallForwarder::LocalExitCallHandler(
            host_call::kSysFutexWaitHandler, forwarder) {}

  absl::optional<Status> AttemptExecute(MessageReader *input,
                                        MessageWriter *output) override {
    // Process futex_wait selector locally.
    return host_call::SysFutexWaitHelper(input, output);
  }
};

class SysFutexWakeExitCallHandler
    : public LocalExitCallForwarder::LocalExitCallHandler {
 public:
  explicit SysFutexWakeExitCallHandler(LocalExitCallForwarder *forwarder)
      : LocalExitCallForwarder::LocalExitCallHandler(
            host_call::kSysFutexWakeHandler, forwarder) {}

  absl::optional<Status> AttemptExecute(MessageReader *input,
                                        MessageWriter *output) override {
    // Process futex_wake selector locally.
    return host_call::SysFutexWakeHelper(input, output);
  }
};

}  // namespace

Status LocalExitCallForwarder::PerformUnknownExit(uint64_t untrusted_selector,
                                                  MessageReader *input,
                                                  MessageWriter *output,
                                                  Client *client) {
  return server_->ExitCallForwarder(untrusted_selector, input, output, client);
}

LocalExitCallForwarder::LocalExitCallForwarder(
    bool exit_logging, const RemoteEnclaveProxyServer *server)
    : LoggingDispatchTable(exit_logging), server_(CHECK_NOTNULL(server)) {}

Status LocalExitCallForwarder::Run(const std::shared_ptr<Client> &client,
                                   void *context, MessageReader *input,
                                   MessageWriter *output) {
  // Context points to LocalExitCallHandler instance.
  LocalExitCallHandler *const handler =
      static_cast<LocalExitCallHandler *>(context);

  auto optional_result = handler->AttemptExecute(input, output);
  if (optional_result.has_value()) {
    return optional_result.value();
  }

  // Impossible. Forward to the proxy.
  return handler->Forward(input, output, client.get());
}

StatusOr<std::unique_ptr<Client::ExitCallProvider>>
LocalExitCallForwarder::Create(bool exit_logging,
                               const RemoteEnclaveProxyServer *server) {
  // Create forwarder for all unregistered exit calls.
  auto exit_call_forwarder =
      absl::WrapUnique(new LocalExitCallForwarder(exit_logging, server));

  // Create exit call handlers that could be handled locally.
  exit_call_forwarder->handlers_.emplace_back(
      absl::make_unique<GetTimeExitCallHandler>(server->communicator(),
                                                exit_call_forwarder.get()));
  exit_call_forwarder->handlers_.emplace_back(
      absl::make_unique<SysFutexWaitExitCallHandler>(
          exit_call_forwarder.get()));

  exit_call_forwarder->handlers_.emplace_back(
      absl::make_unique<SysFutexWakeExitCallHandler>(
          exit_call_forwarder.get()));

  // Register all exit call handlers.
  for (const auto &handler : exit_call_forwarder->handlers_) {
    ASYLO_RETURN_IF_ERROR(handler->Register());
  }

  return std::move(exit_call_forwarder);
}

}  // namespace primitives
}  // namespace asylo
