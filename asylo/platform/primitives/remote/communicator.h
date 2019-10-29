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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_COMMUNICATOR_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_COMMUNICATOR_H_

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/remote/grpc_service.grpc.pb.h"
#include "asylo/platform/primitives/remote/grpc_service.pb.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {
namespace primitives {

// Implements a peer-to-peer RPC connection between an enclave host and an
// enclave target process.
//
// The duplex connection between the two Communicator instances is provided by
// encapsulating both a gRPC server and client on each side. A host Communicator
// object exchanges messages with the target Communicator object by connecting
// its client to target's server, and likewise target's client to the host's
// server. The role of the server is to handle remote RPCs made by a counterpart
// Communicator object's client. The role of the client is to issue RPCs to the
// counterpart.
//
// Thread safety: All methods of the Communicator class are thread safe.
// Reliability: Provided the network is unpartitioned and bandwidth is
// available, Communicator guarantees transfer of complete messages.
//
// A user of a Communicator object must:
// 1.  configure call handlers with set_handler(),
// 2.  launch the gRPC server with StartServer, then
// 3.  start the service loop with ServerRPCLoop() (in its own thread on host,
//     in a donated thread on target),
// 4.  connect the client to the counterpart's server with Connect()
class Communicator {
 public:
  // A record representing an Invoke operation on both caller and callee side.
  // Caller (client) fills in params, invocation_thread_id and selector.
  // Callee (server) reads those and fills in result and optionally status.
  // Once responded, caller (client) reads result and status.
  struct Invocation {
   public:
    virtual ~Invocation() = default;
    MessageReader reader;
    MessageWriter writer;
    Thread::Id invocation_thread_id;
    uint64_t selector;
    Status status;
  };

  // Wrapped smart pointer to CommunicationMessage that ensures access to the
  // message and allows for a callback that (among other things) discards it
  // (the guarantee is that WrappedMessage outlives the message).
  class WrappedMessageDeleter {
   public:
    explicit WrappedMessageDeleter(std::function<void()> discard = nullptr)
        : discard_(discard) {}
    void operator()(CommunicationMessage *message) {
      if (discard_) {
        discard_();
      }
    }

   private:
    std::function<void()> discard_;
  };
  using CommunicationMessagePtr =
      std::unique_ptr<CommunicationMessage, WrappedMessageDeleter>;

  explicit Communicator(bool is_host);
  ~Communicator();

  Communicator(const Communicator &other) = delete;
  Communicator &operator=(const Communicator &other) = delete;

  // Creates gRPC server with 'server_creds' Server credentials.
  // If 'requested_port' is not specified (set to 0), gRPC will choose the
  // server port, which will then be available by server_port(). Returns OK or
  // status if the server did not start.
  ASYLO_MUST_USE_RESULT Status
  StartServer(const std::shared_ptr<::grpc::ServerCredentials> &server_creds,
              int requested_port = 0);

  // Connects gRPC client to the gRPC server with 'remote_address' using
  // 'channel_creds' channel credentials and 'channel_args' channel arguments.
  // Returns OK or error status, if connection failed.
  ASYLO_MUST_USE_RESULT Status Connect(const RemoteProxyConfig &config,
                                       absl::string_view remote_address);

  // Invokes a handler on the remote peer, associated with the |selector|.
  // Creates RPC client-side instance, calls |params_setter| to fill in input
  // parameters, makes an RPC call and schedules |callback| on the same thread
  // Invoke was called on. When |callback| is called with a success status,
  // invocation->result.size() matches |result_reservation|. If any error is
  // detected (even before RPC was actually sent to the server), |callback| is
  // still called.
  void Invoke(
      uint64_t selector,
      const std::function<void(Invocation *invocation)> &params_setter,
      std::function<void(std::unique_ptr<Invocation> invocation)> callback);

  // Disconnects the communicator. Reads and writes to a disconnected
  // communicator will fail. Repeated calls of Disconnect are allowed but have
  // no effect.
  void Disconnect();

  // Sends gRPC server address of this Communicator to the counterpart.
  // Expected to be called by the counterpart Communicator before connecting its
  // gRPC client. Not mandatory: need to be called only when port is assigned
  // dynamically by gRPC builder and not known to the Communicator counterpart
  // beforehand.
  void SendEndPointAddress(absl::string_view address);

  // Waits for gRPC end point address to be received from the counterpart
  // calling SendEndPointAddress.
  std::string WaitForEndPointAddress();

  // Kill matching thread (on target side only) after the signal has been
  // received from the host side that the thread is exiting.
  void DisposeOfThread(Thread::Id exiting_thread_id);

  // Returns true if the communicator is connected and can be used for both
  // reads and writes.
  ASYLO_MUST_USE_RESULT bool IsConnected() const;

  // Installs a server-side handler function that processes each incoming RPC.
  // When certain host thread runs a series of Invoke calls with remote backend
  // primitives, target side Communicator needs to run respective handlers on
  // the same target-side thread, which is referred as a "matching" to the host
  // thread here and below. This is necessary for several reasons:
  //
  // 1) Handlers might pass some information from one to another in thread local
  //    storage, lock/unlock mutexes or allocate memory on a thread-specific
  //    heap.
  // 2) Handlers could (correctly) assume that two different Invoke calls made
  //    on the same thread are never executed in parallel.
  // 3) A handler might make a nested call back to the host side, in which case
  //    the host handler will need to be executed in the context of the original
  //    caller thread - it might need access to the same thread local storage,
  //    make more nested calls to the target side, etc.
  // The concept of thread-matching simulates host-target behavior of
  // local backend primitives: when the untrusted domain makes a call to the
  // trusted domain, the trusted call body is executed on the same thread as the
  // caller. The caller then synchronously waits for the callee to return. The
  // callee is allowed to make nested calls to the untrusted domain still within
  // the same thread.
  void set_handler(
      std::function<void(std::unique_ptr<Invocation> invocation)> handler);

  // Runs service side Rpc processing loop. Host side runs it on a
  // dedicated thread, while target side donates main thread to run it (and
  // therefore does not finish until ServerRpcLoop exits).
  void ServerRpcLoop();

  // Returns true if running on the host side of the communicator.
  bool is_host() const { return is_host_; }

  // Returns port assigned when creating the server.
  int server_port() const;

  // Accessor to the last time received from the host (valid only
  // on target Communicator, has no use on the host one).
  absl::optional<int64_t> last_host_time_nanos() const {
    return *last_host_time_nanos_.ReaderLock();
  }

 private:
  class ClientImpl;
  // gRPC service and client implementation.
  class ServiceImpl;
  // A queue of each worker thread that handles messages dispatched to it with
  // QueueMessageForThread. A new queue is added whenever the first Invoke call
  // takes place on a specific host thread.
  class ThreadActivityWorkQueue;

  // Sends |message| (request or response) to the counterpart Communicator.
  Status SendCommunication(const CommunicationMessage &message);

  // Assigns |wrapped_message| to be processed on the thread that matches its
  // invocation_thread_id.
  void QueueMessageForThread(CommunicationMessagePtr wrapped_message);

  // Locates or creates ThreadActivityWorkQueue for the given host thread id
  // (both on host and target side).
  ASYLO_MUST_USE_RESULT StatusOr<ThreadActivityWorkQueue *>
  LocateOrCreateThreadActivityWorkQueue(Thread::Id invocation_thread_id);

  // Runs a loop getting wrapped messages and processing requests on the current
  // thread until response is received (returns it) or thread is signaled
  // to exit (returning status).
  StatusOr<CommunicationMessagePtr> MessageLoop();

  // Creates gRPC stub for writing.
  ASYLO_MUST_USE_RESULT Status CreateStub(const RemoteProxyConfig &config,
                                          absl::string_view remote_address);

  // Verifies that CommunicationMessage is correctly formed.
  // Returns status if not.
  static Status IsMessageValid(const CommunicationMessage &message);

  // Setters for the last time received from the host (valid only
  // on target Communicator, have no use on the host one).
  void set_host_time_nanos(int64_t time_nanos) {
    *last_host_time_nanos_.Lock() = time_nanos;
  }
  void invalidate_host_time_nanos() {
    *last_host_time_nanos_.Lock() = absl::nullopt;
  }

  // Static map of registered communicators, used by host thread exiter callback
  // to signal matching target threads to exit.
  static MutexGuarded<absl::flat_hash_set<Communicator *>>
      *active_communicators();

  // Host/target flag.
  const bool is_host_;

  // gRPC client and service.
  std::unique_ptr<ClientImpl> client_;
  std::unique_ptr<ServiceImpl> service_;

  // Flags indicating whether server and client are ready.
  // Set to false by constructor, switched to true when server and client are
  // connected (respectively), reset to false by either Disconnect call or
  // by receiving notification from the communicator counterpart.
  std::atomic<bool> is_server_ready_;
  std::atomic<bool> is_client_ready_;

  // Last time stamp received from the host (set only on target Communicator).
  // Expires after time specified by --host_time_nanos_expiration flag.
  MutexGuarded<absl::optional<int64_t>> last_host_time_nanos_;

  // Host-side only: exit callback stored in thread-local storage and
  // automatically invoked when the thread exits and thread-local objects are
  // destructed.
  static thread_local std::unique_ptr<Cleanup> thread_exiter_;

  // Pointer to the ThreadActivityWorkQueue for the current thread, cached here
  // in order to reduce contention on threads_map_. It is captured for target
  // threads at the time a worker thread begins executing, and for host threads
  // the first time Invoke is called by that thread. The cached value never
  // changes until the thread terminates or all communicators destruct.
  ABSL_CONST_INIT static thread_local ThreadActivityWorkQueue
      *current_thread_context_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_COMMUNICATOR_H_
