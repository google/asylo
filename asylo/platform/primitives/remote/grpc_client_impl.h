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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_GRPC_CLIENT_IMPL_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_GRPC_CLIENT_IMPL_H_

#include <atomic>
#include <cstdint>
#include <memory>

#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/grpc_service.grpc.pb.h"
#include "asylo/platform/primitives/remote/grpc_service.pb.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {
namespace primitives {

class Communicator::ClientImpl {
 public:
  ~ClientImpl();

  ClientImpl(const ClientImpl &other) = delete;
  ClientImpl &operator=(const ClientImpl &other) = delete;

  // Factory method that creates a gRPC client instance used by Communicator.
  // Returns status if there was an error.
  static StatusOr<std::unique_ptr<ClientImpl>> Create(
      const RemoteProxyConfig &config, absl::string_view remote_address,
      Communicator *const communicator);

  // Sends CommuncationMessage (request or response) to the counterpart
  // Communicator.
  Status SendCommunication(const CommunicationMessage &message);

  // Sends disconnect request to the Communicator counterpart, triggering it to
  // shut down.
  void SendDisconnect();

  // Sends end point address to the counterpart. Not mandatory, expected to be
  // used only when end point address is assigned dynamically and not known to
  // the counterpart.
  void SendEndPointAddress(absl::string_view address);

  // Sends notification from host to target-side Communicator to dispose of
  // the thread matching exiting_thread_id (which is exiting and will no longer
  // make Invoke calls).
  void SendDisposeOfThread(Thread::Id exiting_thread_id);

  // Runs Invocation
  Status RunInvocation(Communicator::Invocation *invocation);

 private:
  // Constructor, used by factory method only.
  explicit ClientImpl(Communicator *communicator);

  // Generates atomically increasing monotonic sequence number
  // for request-response match verification.
  uint64_t GenerateSequenceNumber();

  // gRPC client stub used for writing messages over gRPC.
  std::shared_ptr<::grpc::Channel> grpc_channel_;
  std::unique_ptr<CommunicatorService::Stub> grpc_stub_;

  // SequenceNumber generation.
  std::atomic<uint64_t> sequence_number_;

  // Metrics OpenCensusClient for ProcSystemService. Exports metrics via
  // OpenCensus.
  // Note: Exporters still need to be setup per the OpenCensus documentation. An
  // example of setting up an OpenCensus exporter can be found here:
  // https://opencensus.io/quickstart/cpp/metrics/#exporting-to-prometheus
  std::unique_ptr<OpenCensusClient> open_census_client_;

  // Communicator owner.
  Communicator *const communicator_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_GRPC_CLIENT_IMPL_H_
