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

#include <cstdint>
#include <memory>
#include <utility>

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/parameter_stack.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

// This file declares the primitive API exposed to untrusted application code by
// the Asylo runtime. Each Asylo backend is responsible for providing an
// implementation of this interface.

// To support multiple implementations, the interface defines a generic "Enclave
// Backend" concept which every backend must implement. An enclave backend is a
// structure compatible with:
//
// struct EnclaveBackend {
//   // Load an enclave, returning a Client or error status.
//   static StatusOr<std::shared_ptr<Client>> Load(...);
// };

// Loads an enclave. This template function should be instantiated with an
// "Enclave Backend" parameter exported by a concrete implementation of the
// "Backend" concept.
template <typename Backend, typename... Args>
StatusOr<std::shared_ptr<class Client>> LoadEnclave(Args &&... args) {
  return Backend::Load(std::forward<Args>(args)...);
}

// Callback structure for dispatching messages from the enclave.
struct ExitHandler {
  using Callback =
      std::function<Status(std::shared_ptr<class Client> enclave, void *,
                           ParameterStack<malloc, free> *)>;

  ExitHandler() : context(nullptr) {}

  // Initializes an exit handler with a callback.
  explicit ExitHandler(Callback callback)
      : callback(callback), context(nullptr) {}

  // Initializes an exit handler with a callback and a context pointer.
  ExitHandler(Callback callback, void *context)
      : callback(callback), context(context) {}

  // Returns true if this handler is uninitialized.
  bool IsNull() const { return callback == nullptr; }

  // Callback function to invoke for this exit.
  Callback callback;

  // Uninterpreted data passed by the runtime to invocations of the handler.
  void *context;
};

// ParameterStack to be used in untrusted code.
using UntrustedParameterStack = ParameterStack<malloc, free>;

// A reference to an enclave held by untrusted code.
class Client : public std::enable_shared_from_this<Client> {
 public:
  // An interface to a provider of enclave exit calls.
  class ExitCallProvider {
   public:
    virtual ~ExitCallProvider() = default;

    // Registers a callback as the handler routine for an enclave exit point
    // `untrusted_selector`. Returns an error code if a handler has already been
    // registered for `trusted_selector` or if an invalid selector value is
    // passed.
    virtual Status RegisterExitHandler(uint64_t untrusted_selector,
                                       const ExitHandler &handler)
        ASYLO_MUST_USE_RESULT = 0;

    // Finds and invokes an exit handler. Returns an error status on failure.
    virtual Status InvokeExitHandler(uint64_t untrusted_selector,
                                     UntrustedParameterStack *params,
                                     Client *client) ASYLO_MUST_USE_RESULT = 0;
  };

  // RAII wrapper that sets thread-local enclave client reference and resets
  // it when going out of scope.
  class ScopedCurrentClient {
   public:
    explicit ScopedCurrentClient(Client *client)
        : saved_client_(Client::current_client_) {
      current_client_ = client;
    }
    ~ScopedCurrentClient() { current_client_ = saved_client_; }

    ScopedCurrentClient(const ScopedCurrentClient &other) = delete;
    ScopedCurrentClient &operator=(const ScopedCurrentClient &other) = delete;

   private:
    Client *saved_client_;
  };

  virtual ~Client() = default;

  // Returns true if the enclave has been destroyed, or if it is marked for
  // destruction pending the completion of an operation by another thread. A
  // closed enclave may not be entered and will not accept messages.
  virtual bool IsClosed() const = 0;

  // Marks the enclave for destruction, possibily pending the completion of
  // operations by concurrent client threads.
  virtual Status Destroy() = 0;

  /// Returns the name of the enclave.
  ///
  /// \return The name of the enclave.
  virtual const absl::string_view &Name() const { return name_; }

  // Enters the enclave synchronously at an entry point to trusted code
  // designated by `selector`.
  // Input `params` is copied into the enclave, which occurs locally inside the
  // same address space.
  // Conversely, results are copied and returned in 'params'.
  Status EnclaveCall(uint64_t selector,
                     UntrustedParameterStack *params) ASYLO_MUST_USE_RESULT;

  // Enclave exit callback function shared with the enclave.
  static PrimitiveStatus ExitCallback(uint64_t untrusted_selector,
                                      UntrustedParameterStack *params);

  // Accessor to exit call provider.
  ExitCallProvider *exit_call_provider() { return exit_call_provider_.get(); }

 protected:
  Client(const absl::string_view name,
      std::unique_ptr<ExitCallProvider> exit_call_provider)
      : exit_call_provider_(std::move(exit_call_provider)), name_(name) {}

  // Provides implementation of EnclaveCall.
  virtual Status EnclaveCallInternal(uint64_t selector,
                                     UntrustedParameterStack *params)
      ASYLO_MUST_USE_RESULT = 0;

 private:
  // Exit call provider for the enclave.
  const std::unique_ptr<ExitCallProvider> exit_call_provider_;

  // Thread-local reference to the enclave that makes exit call.
  // Can be set by EnclaveCall, enclave loader.
  static thread_local Client *current_client_;

  // Enclave name.
  absl::string_view name_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UNTRUSTED_PRIMITIVES_H_
