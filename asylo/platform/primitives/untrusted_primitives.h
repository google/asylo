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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UNTRUSTED_PRIMITIVES_H_
#define ASYLO_PLATFORM_PRIMITIVES_UNTRUSTED_PRIMITIVES_H_

#include <unistd.h>

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

/// Loads an enclave.
///
/// This template function should be instantiated with an "Enclave Backend"
/// parameter exported by a concrete implementation of the "Backend" concept.
template <typename Backend, typename... Args>
StatusOr<std::shared_ptr<class Client>> LoadEnclave(Args &&... args) {
  return Backend::Load(std::forward<Args>(args)...);
}

/// \class ExitHandler untrusted_primitives.h @untrusted_primitives
/// Callback structure for dispatching messages from the enclave.
struct ExitHandler {
  using Callback =
      std::function<Status(std::shared_ptr<class Client> enclave, void *context,
                           MessageReader *input, MessageWriter *output)>;

  ExitHandler() : ExitHandler(/*callback=*/nullptr, /*context=*/nullptr) {}

  /// Initializes an exit handler with a callback.
  ///
  /// \param callback The callback this handler uses.
  explicit ExitHandler(Callback callback)
      : ExitHandler(callback, /*context=*/nullptr) {}

  /// Initializes an exit handler with a callback and a context pointer.
  ///
  /// \param callback The callback this handler uses.
  /// \param context A type-erased non-owned pointer that is passed to the
  ///    callback when called. Since an ExitHandler is registered in an
  ///    client-global context, the object should live as long as the client.
  ExitHandler(Callback callback, void *context)
      : callback(callback), context(context) {}

  /// A predicate for whether the callback is initialized.
  ///
  /// \returns true if this handler is uninitialized.
  bool IsNull() const { return callback == nullptr; }

  /// Implicit bool conversion for null checks.
  operator bool() const { return IsNull(); }

  /// Callback function to invoke for this exit.
  Callback callback;

  /// Uninterpreted data passed by the runtime to invocations of the handler.
  void *context;
};

/// \class Client untrusted_primitives.h @untrusted_primitives
/// A reference to an enclave held by untrusted code.
///
/// This declares the primitive API exposed to untrusted application code by
/// the Asylo runtime. Each Asylo backend is responsible for providing an
/// implementation of this interface.
/// To support multiple implementations, the interface defines a generic
/// "Enclave Backend" concept which every backend must implement. An enclave
/// backend is a structure compatible with:
///
/// ```
/// struct EnclaveBackend {
///   // Load an enclave, returning a Client or error status.
///   static StatusOr<std::shared_ptr<Client>> Load(...);
/// };
/// ```
class Client : public std::enable_shared_from_this<Client> {
 public:
  /// An interface to a provider of enclave exit calls.
  class ExitCallProvider {
   public:
    virtual ~ExitCallProvider() = default;

    /// Registers a callback as the handler routine for an enclave exit point
    /// `untrusted_selector`.
    ///
    /// \param untrusted_selector The identification number an enclave will use
    ///    to select the registered handler, `handler`.
    /// \param handler The representation of a callable untrusted function.
    /// \returns If a handler has already been registered for `trusted_selector`
    /// or if an invalid selector value is passed, returns an error status,
    /// otherwise Ok.
    virtual Status RegisterExitHandler(uint64_t untrusted_selector,
                                       const ExitHandler &handler)
        ASYLO_MUST_USE_RESULT = 0;

    /// Finds and invokes an exit handler.
    ///
    /// \param untrusted_selector The identification number for the called
    ///    untrusted function.
    /// \param input A pointer to a MessageReader from which the function
    ///    implementation can read the arguments the enclave wrote.
    /// \param output A pointer to a MessageWriter to which the function will
    ///    write the function's outputs.
    /// \param client A pointer to the client that is exiting.
    /// \returns an error status on failure, otherwise Ok.
    virtual Status InvokeExitHandler(uint64_t untrusted_selector,
                                     MessageReader *input,
                                     MessageWriter *output,
                                     Client *client) ASYLO_MUST_USE_RESULT = 0;
  };

  /// An RAII wrapper that sets thread-local enclave "current client" reference
  /// on construction and resets it to the previous value when destroyed.
  class ScopedCurrentClient {
   public:
    /// Constructs a "scope object" to set the current client pointer for the
    /// lifetime of the object.
    ///
    /// \param client An unowned pointer to the new current client.
    explicit ScopedCurrentClient(Client *client)
        : saved_client_(Client::current_client_), pid_(getpid()) {
      current_client_ = client;
    }
    ~ScopedCurrentClient();

    ScopedCurrentClient(const ScopedCurrentClient &other) = delete;
    ScopedCurrentClient &operator=(const ScopedCurrentClient &other) = delete;

   private:
    Client *const saved_client_;
    const pid_t pid_;
  };

  virtual ~Client() { ReleaseMemory(); }

  /// An overridable handler registration method.
  ///
  /// This allows backend implementations to register special-purpose exit
  /// handlers that might only be appropriate to that backend. The default
  /// implementation registers nothing and returns Ok.
  ///
  /// \returns An error on failure, or Ok.
  virtual Status RegisterExitHandlers() ASYLO_MUST_USE_RESULT;

  /// A predicate for whether the enclave may be entered or will accept
  /// messages.
  ///
  /// \returns True if the enclave has been destroyed, or if it is marked for
  /// destruction pending the completion of an operation by another thread.
  virtual bool IsClosed() const = 0;

  // Marks the enclave for destruction, possibly pending the completion of
  // operations by concurrent client threads.
  virtual Status Destroy() = 0;

  /// A getter for the enclave name.
  ///
  /// Enclave names are used for fetching client instances from the enclave
  /// manager.
  ///
  /// \returns The name of the enclave.
  virtual absl::string_view Name() const { return name_; }

  /// Stores `this` as the active thread's "current client".
  ///
  /// This should only be called if an enclave entry happens without going
  /// through a regular enclave entry point (like a fork from inside the
  /// enclave).
  void SetCurrentClient();

  /// A static getter for the current client.
  ///
  /// \returns A pointer to the active thread's current client.
  static Client *GetCurrentClient();

  /// Enters the enclave synchronously at an entry point to trusted code
  /// designated by `selector`.
  /// Input `input` is copied into the enclave, which may occur locally inside
  /// the same address space as the caller or remotely via RPC.
  /// Conversely, results are copied and returned in 'output'.
  ///
  /// \param selector The identification number to select a registered
  ///    handler in the enclave.
  /// \param input A pointer to a MessageWriter, into which all call inputs must
  ///    be pushed.
  /// \param output A pointer to a MessageReader from which to read outputs from
  ///    the call.
  /// \returns A status for the call action, since the call itself may fail.
  Status EnclaveCall(uint64_t selector, MessageWriter *input,
                     MessageReader *output) ASYLO_MUST_USE_RESULT;

  /// Enclave exit callback function shared with the enclave.
  ///
  /// \param untrusted_selector The identification number to select a registered
  ///    handler in the current client.
  /// \param in A pointer to a MessageReader, from which all inputs are read.
  /// \param out A pointer to a MessageWriter, into which all call outputs are
  ///    written.
  /// \returns A PrimitiveStatus for the call action, since the call itself may
  ///    fail.
  static PrimitiveStatus ExitCallback(uint64_t untrusted_selector,
                                      MessageReader *in, MessageWriter *out);

  /// Accessor to the client's exit call provider.
  ///
  /// \returns A mutable pointer to the client's ExitCallProvider.
  ExitCallProvider *exit_call_provider() { return exit_call_provider_.get(); }

  /// Register memory to be freed upon enclave destruction.
  ///
  /// \param mem A pointer to be passed to free on enclave exit.
  virtual void RegisterMemory(void *mem) {
    memory_to_free_.Lock()->emplace_back(mem);
  }

  /// Frees enclave resources registered to the client.
  virtual void ReleaseMemory() {
    auto to_free = memory_to_free_.Lock();
    for (auto ptr : *to_free) {
      free(ptr);
    }
    to_free->clear();
  }

 protected:
  /// Constructs a client, reserved for only backend implementations.
  ///
  /// \param name The name of the enclave.
  /// \param exit_call_provider A pointer an ExitCallProvider that the Client
  ///    takes ownership of. The provider is the source of all `ExitHandler`s.
  Client(const absl::string_view name,
         std::unique_ptr<ExitCallProvider> exit_call_provider)
      : exit_call_provider_(std::move(exit_call_provider)),
        name_(name) {}

  /// Provides implementation of EnclaveCall.
  ///
  /// This method is virtual for backends to override. The public EnclaveCall
  /// method provides necessary boilerplate around each call to this
  /// implementation.
  ///
  /// \param selector The identification number to select a registered
  ///    handler in the enclave.
  /// \param input A pointer to a MessageWriter, into which all call inputs must
  ///    be pushed.
  /// \param output A pointer to a MessageReader from which to read outputs from
  ///    the call.
  /// \returns A status for the call action, since the call itself may fail.
  virtual Status EnclaveCallInternal(uint64_t selector, MessageWriter *input,
                                     MessageReader *output)
      ASYLO_MUST_USE_RESULT = 0;

 private:
  // Exit call provider for the enclave.
  const std::unique_ptr<ExitCallProvider> exit_call_provider_;

  // Thread-local reference to the enclave that makes exit call.
  // Can be set by EnclaveCall, enclave loader.
  static thread_local Client *current_client_;

  // Enclave name.
  absl::string_view name_;

  // A collection of memory to free upon enclave exit.
  MutexGuarded<std::vector<void *>> memory_to_free_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UNTRUSTED_PRIMITIVES_H_
