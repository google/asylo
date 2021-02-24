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

#ifndef ASYLO_PLATFORM_CORE_ENCLAVE_MANAGER_H_
#define ASYLO_PLATFORM_CORE_ENCLAVE_MANAGER_H_

// Declares the enclave client API, providing types and methods for loading,
// accessing, and finalizing enclaves.

#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/core/enclave_client.h"
#include "asylo/platform/core/enclave_config_util.h"
#include "asylo/platform/core/shared_resource_manager.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"  // IWYU pragma: export
#include "asylo/util/statusor.h"

namespace asylo {
class EnclaveLoader;

/// Enclave Manager configuration.
/// \deprecated EnclaveManager no longer needs to be configured.
class EnclaveManagerOptions {};

/// A manager object responsible for creating and managing enclave instances.
///
/// EnclaveManager is a singleton class that tracks the status of enclaves
/// within a process. Users can get a pointer to the singleton instance by
/// calling the static Instance() method.
///
/// NOTE: Configuring the EnclaveManager with Configure() is no longer required
/// before obtaining a pointer to the singleton instance.
///
/// \deprecated Users of this class first supply a configuration using the
/// static Configure() method, and then get a pointer to the singleton instance
/// as specified by this configuration by calling the static Instance() method.
class EnclaveManager {
 public:
  /// Fetches the EnclaveManager singleton instance.
  ///
  /// \return A StatusOr containing either the global EnclaveManager instance or
  ///         an error describing why it could not be returned.
  static StatusOr<EnclaveManager *> Instance();

  /// \deprecated EnclaveManager no longer needs to be configured.
  /// Configures the enclave manager.
  ///
  /// \param options Configuration options as described in
  ///                EnclaveManagerOptions.
  static Status Configure(const EnclaveManagerOptions &options);

  /// Loads an enclave.
  ///
  /// Loads a new enclave utilizing the passed enclave backend loader
  /// configuration settings. The loaded enclave is bound to the value of field
  /// `name` set in |load_config|.
  /// The enclave is initialized with custom enclave config settings if the
  /// `config` field is set in |load_config|. Else, the enclave is initialized
  /// with default Asylo enclave config settings.
  ///
  /// It is an error to specify a name which is already bound to an enclave.
  ///
  /// Example:
  /// 1) Load an enclave with custom enclave config settings
  ///
  /// ```
  ///  EnclaveConfig config;
  ///  ... // populate config proto.
  ///
  ///  EnclaveLoadConfig load_config;
  ///  load_config.set_name("example");
  ///  load_config.set_config(config);
  ///
  ///  load_config.SetExtension(example_backend_extension);
  ///  ... // populate Asylo backend extension proto.
  ///  LoadEnclave(load_config);
  /// ```
  /// 2) Load an enclave with default enclave config settings
  ///
  /// ```
  ///  EnclaveLoadConfig load_config;
  ///  load_config.set_name("example");
  ///  load_config.SetExtension(example_backend_extension);
  ///  ... // populate Asylo backend extension proto.
  ///  LoadEnclave(load_config);
  /// ```
  /// \param load_config Backend configuration options to load an enclave
  Status LoadEnclave(const EnclaveLoadConfig &load_config);

  /// Loads an enclave.
  ///
  /// Loads a new enclave with default enclave config settings and binds it to a
  /// name. The actual work of opening the enclave is delegated to the passed
  /// loader object.
  ///
  /// It is an error to specify a name which is already bound to an enclave.
  ///
  /// Example:
  /// ```
  ///   LoadEnclave("/EchoEnclave", SgxLoader("echoService.so"));
  /// ```
  ///
  /// \param name Name to bind the loaded enclave under.
  /// \param loader Configured enclave loader to load from.
  /// \param base_address Start address to load enclave(optional).
  /// \param enclave_size The size of the enclave in memory(only needed if
  /// |base_address| is specified).
  /// \deprecated Use LoadEnclave(const EnclaveLoadConfig &load_config)
  Status LoadEnclave(absl::string_view name, const EnclaveLoader &loader,
                     void *base_address = nullptr,
                     const size_t enclave_size = 0);

  /// Loads an enclave.
  ///
  /// Loads a new enclave with custom enclave config settings and binds it to a
  /// name. The actual work of opening the enclave is delegated to the passed
  /// loader object.
  ///
  /// It is an error to specify a name which is already bound to an enclave.
  ///
  /// Example:
  ///
  /// ```
  ///  EnclaveConfig config;
  ///  ... // populate config proto.
  ///  LoadEnclave("/EchoEnclave", SgxLoader("echoService.so"), config);
  /// ```
  ///
  /// \param name Name to bind the loaded enclave under.
  /// \param loader Configured enclave loader to load from.
  /// \param config Enclave configuration to launch the enclave with.
  /// \param base_address Start address to load enclave(optional).
  /// \param enclave_size The size of the enclave in memory(only needed if
  /// |base_address| is specified).
  /// \deprecated Use LoadEnclave(const EnclaveLoadConfig &load_config)
  Status LoadEnclave(absl::string_view name, const EnclaveLoader &loader,
                     EnclaveConfig config, void *base_address = nullptr,
                     const size_t enclave_size = 0);

  /// Fetches a client to a loaded enclave.
  ///
  /// \param name The name of an EnclaveClient that may be registered in the
  ///             EnclaveManager.
  /// \return A mutable pointer to the EnclaveClient if the name is
  ///         registered. Otherwise returns nullptr.
  EnclaveClient *GetClient(absl::string_view name) const
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  /// Returns the name of an enclave client.
  ///
  /// \param client A pointer to a client that may be registered in the
  ///               EnclaveManager.
  /// \return The name of an enclave client. If no enclave matches `client` the
  ///         empty string will be returned.
  const absl::string_view GetName(const EnclaveClient *client) const
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  /// Destroys an enclave.
  ///
  /// Destroys an enclave. This method calls `client's` EnterAndFinalize entry
  /// point with final_input unless `skip_finalize` is true, then calls
  /// `client's` DestroyEnclave method, and then removes client's name from the
  /// EnclaveManager client registry. The manager owns the client, so removing
  /// it calls client's destructor and frees its memory. The client is destroyed
  /// regardless of whether `client's` EnterAndFinalize method succeeds or
  /// fails. This method must not be invoked more than once.
  ///
  /// \param client A client attached to the enclave to destroy.
  /// \param final_input Input to pass the enclave's finalizer.
  /// \param skip_finalize If true, the enclave is destroyed without invoking
  ///                      its Finalize method.
  /// \return The Status returned by the enclave's Finalize method, or an
  ///         OK Status if that was skipped.
  Status DestroyEnclave(EnclaveClient *client, const EnclaveFinal &final_input,
                        bool skip_finalize = false)
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  /// Fetches the shared resource manager object.
  ///
  /// \return The SharedResourceManager instance.
  SharedResourceManager *shared_resources() {
    return &shared_resource_manager_;
  }

  /// Fetches the shared resource manager object.
  ///
  /// \return The SharedResourceManager instance.
  const SharedResourceManager *shared_resources() const {
    return &shared_resource_manager_;
  }

  /// Get the load config of an enclave. This should only be used during fork
  /// in order to load an enclave with the same load config as the parent.
  EnclaveLoadConfig GetLoadConfigFromClient(EnclaveClient *client)
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

 private:
  EnclaveManager() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
  EnclaveManager(EnclaveManager const &) = delete;
  EnclaveManager &operator=(EnclaveManager const &) = delete;

  // Loads a fake enclave with custom enclave config settings and binds it to a
  // name. An enclave loaded using this interface doesn't build on any Asylo
  // backend technology and is strictly meant to be used for testing only. The
  // actual work of opening the enclave is delegated to the passed loader
  // object.
  Status LoadFakeEnclave(absl::string_view name, const EnclaveLoader &loader,
                         const EnclaveConfig &config,
                         void *base_address = nullptr,
                         const size_t enclave_size = 0)
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  // Deletes an enclave client reference that points to an enclave that no
  // longer exists. This should only happen during fork.
  void RemoveEnclaveReference(absl::string_view name)
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  // Manager object for untrusted resources shared with enclaves.
  SharedResourceManager shared_resource_manager_;

  // Value synchronized to CLOCK_MONOTONIC by the worker loop.
  std::atomic<int64_t> clock_monotonic_;

  // Value synchronized to CLOCK_REALTIME by the worker loop.
  std::atomic<int64_t> clock_realtime_;

  // A mutex guarding |client_by_name_|, |name_by_client_|, and
  // |loader_by_client_| tables.
  mutable absl::Mutex client_table_lock_;

  absl::flat_hash_map<std::string, std::unique_ptr<EnclaveClient>>
      client_by_name_ ABSL_GUARDED_BY(client_table_lock_);
  absl::flat_hash_map<const EnclaveClient *, std::string> name_by_client_
      ABSL_GUARDED_BY(client_table_lock_);

  absl::flat_hash_map<const EnclaveClient *, EnclaveLoadConfig>
      load_config_by_client_ ABSL_GUARDED_BY(client_table_lock_);

  // Mutex guarding the static state of this class.
  static absl::Mutex mu_;

  // Singleton instance of this class.
  static EnclaveManager *instance_ ABSL_GUARDED_BY(mu_);
};

/// An abstract enclave loader.
///
/// Host applications must load an enclave before using it. This is accomplished
/// via an architecture specific implementation of the EnclaveLoader interface.
class EnclaveLoader {
 public:
  virtual ~EnclaveLoader() = default;

 protected:
  // Only allow the enclave loading via the manager object.
  friend class EnclaveManager;

  // Loads an enclave, returning a pointer to a client on success and a non-ok
  // status on failure.
  virtual StatusOr<std::unique_ptr<EnclaveClient>> LoadEnclave(
      absl::string_view name) const {
    EnclaveConfig config;
    return LoadEnclave(name, /*base_address=*/nullptr, /*enclave_size=*/0,
                       config);
  }

  // Loads an enclave at the specified address, returning a pointer to a client
  // on success and a non-ok status on failure.
  virtual StatusOr<std::unique_ptr<EnclaveClient>> LoadEnclave(
      absl::string_view name, void *base_address, const size_t enclave_size,
      const EnclaveConfig &config) const {
    return absl::InternalError(
        "EnclaveLoader::LoadEnclave not implemented for test enclave");
  }

  virtual EnclaveLoadConfig GetEnclaveLoadConfig() const = 0;
};

// Loads a new enclave with the provided parent enclave name, base virtual
// address and enclave size, as part of servicing a trusted fork() call inside
// the enclave. Returns a pointer to the primitives Client of the enclave
// loaded. The method does not set the current_client of the primitives Client
// with the Client it returns. That is the responsibility of the caller, if
// desired.
// This method currently only supports SGX, since fork is only supported for
// local SGX.
primitives::Client *LoadEnclaveInChildProcess(absl::string_view enclave_name,
                                              void *enclave_base_address,
                                              size_t enclave_size);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ENCLAVE_MANAGER_H_
