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
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/arch/fork.pb.h"
#include "asylo/platform/core/enclave_client.h"
#include "asylo/platform/core/enclave_config_util.h"
#include "asylo/platform/core/shared_resource_manager.h"
#include "asylo/platform/primitives/enclave_type.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"  // IWYU pragma: export
#include "asylo/util/statusor.h"

namespace asylo {
class EnclaveLoader;

/// Enclave Manager configuration.
class EnclaveManagerOptions {
 public:
  /// Configuration server connection attributes.
  ///
  /// A part of an enclave's configuration is expected to be the same across all
  /// enclaves running under a single instance of an OS. An Enclave manager can
  /// obtain such configuration from the Asylo daemon running on the system.
  /// Alternately, the creator of the enclave manager can directly provide such
  /// configuration to the enclave manager. To this end, an
  /// EnclaveManagerOptions instance either holds the information necessary for
  /// connecting to the config server, or holds a HostConfig proto. If the
  /// enclave manager is configured with an options object containing the
  /// server-connection information, the enclave manager obtains the necessary
  /// information by contacting the Asylo daemon. Else, the enclave manager
  /// directly uses the HostConfig info stored within the options structure.
  ///
  /// The ConfigServerConnectionAttributes struct holds information necessary
  /// for contacting the config server running inside the Asylo daemon.
  struct ConfigServerConnectionAttributes {
    ConfigServerConnectionAttributes(absl::string_view address,
                                     absl::Duration timeout)
        : server_address(address), connection_timeout(std::move(timeout)) {}

    std::string server_address;
    absl::Duration connection_timeout;
  };

  /// Constructs a default EnclaveManagerOptions object.
  EnclaveManagerOptions();

  /// Configures a connection to the config server.
  ///
  /// Sets the information necessary for contacting the config server within the
  /// Asylo daemon.
  ///
  /// \return A reference to this EnclaveManagerOptions object.
  EnclaveManagerOptions &set_config_server_connection_attributes(
      absl::string_view address, absl::Duration timeout);

  /// Sets the HostConfig proto within this object.
  ///
  /// \return A reference to this EnclaveManagerOptions object.
  EnclaveManagerOptions &set_host_config(HostConfig config);

  /// Returns the address of the configuration server.
  ///
  /// \return The address of the server from which the HostConfig information
  ///         can be obtained. Returns an error if
  ///         ConfigServerConnectionAttributes are not set.
  StatusOr<absl::string_view> get_config_server_address() const;

  /// Returns the configuration server connection timeout.
  ///
  /// \return The connection timeout for the server from which the HostConfig
  ///         information can be obtained, or an error if
  ///         ConfigServerConnectionAttributes are not set.
  StatusOr<absl::Duration> get_config_server_connection_timeout() const;

  /// Returns the embedded HostConfig object.
  ///
  /// \return The HostConfig information embedded within this object, or an
  ///         error if such information is not embedded within the object.
  StatusOr<HostConfig> get_host_config() const;

  /// Returns true if a HostConfig instance is embedded in this object.
  bool holds_host_config() const;

 private:
  // A variant that either holds information necessary for connecting to the
  // config server or a HostConfig proto.
  absl::variant<ConfigServerConnectionAttributes, HostConfig> host_config_info_;
};

/// A manager object responsible for creating and managing enclave instances.
///
/// EnclaveManager is a singleton class that tracks the status of enclaves
/// within a process. Users of this class first supply a configuration using the
/// static Configure() method, and then get a pointer to the singleton instance
/// as specified by this configuration by calling the static Instance() method.
/// Note that the EnclaveManager class must be configured before the instance
/// pointer can be obtained.
///
/// The EnclaveManager::Configure() method takes an instance of the
/// EnclaveManagerOptions as its only input. This instance can be configured by
/// calling its public setter methods. Note that these setter methods return an
/// instance of the EnclaveManagerOptions() by reference so that the various
/// setters could be chained together.
///
/// Example Usage:
/// ```
///   EnclaveManager::Configure(
///     EnclaveManagerOptions()
///         .set_config_server_connection_attributes(
///             "[::]:8000",
///             absl::Milliseconds(100)));
///   auto manager_result = EnclaveManager::Instance();
///   if (!manager_result.ok()) {
///     LOG(QFATAL) << manager_result.status();
///   }
///   EnclaveManager *manager = manager_result.ValueOrDie();
///   ...
/// ```
///
/// One of the responsibilities of the EnclaveManager class is to provide sane
/// initial configuration to the enclaves it launches. The contents of the
/// EnclaveManagerOptions instance control how the default values for the
/// configuration are chosen.
class EnclaveManager {
 public:
  /// Fetches the EnclaveManager singleton instance.
  ///
  /// \return A StatusOr containing either the global EnclaveManager instance or
  ///         an error describing why it could not be returned.
  static StatusOr<EnclaveManager *> Instance();

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

  // Retrieves and returns a HostConfig proto as specified by the
  // EnclaveManagerOptions which the EnclaveManager was configured when its
  // sngleton instance was created.
  HostConfig GetHostConfig() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

  // Loads a fake enclave with custom enclave config settings and binds it to a
  // name. An enclave loaded using this interface doesn't build on any Asylo
  // backend technology and is strictly meant to be used for testing only. The
  // actual work of opening the enclave is delegated to the passed loader
  // object.
  Status LoadFakeEnclave(absl::string_view name,
                         const EnclaveLoader &loader,
                         const EnclaveConfig &config,
                         void *base_address = nullptr,
                         const size_t enclave_size = 0)
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  // Deletes an enclave client reference that points to an enclave that no
  // longer exists. This should only happen during fork.
  void RemoveEnclaveReference(absl::string_view name)
      ABSL_LOCKS_EXCLUDED(client_table_lock_);

  // Create a thread to periodically update logic.
  void SpawnWorkerThread();

  // Top level loop run by the background worker thread.
  void WorkerLoop();

  // Execute a single iteration of the work loop.
  void Tick();

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

  // A part of the configuration for enclaves launched by the enclave manager
  // comes from the Asylo daemon. This member caches such configuration.
  HostConfig host_config_;

  // Mutex guarding the static state of this class.
  static absl::Mutex mu_;

  // Indication whether the class has been configured so that an instance could
  // be created.
  static bool configured_ ABSL_GUARDED_BY(mu_);

  // Configuration options for this class.
  static EnclaveManagerOptions *options_ ABSL_GUARDED_BY(mu_);

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
      const EnclaveConfig &config) const = 0;

  // Gets a copy of the loader that loaded a previous enclave. This is only used
  // by fork to load a child enclave with the same loader as the parent.
  virtual StatusOr<std::unique_ptr<EnclaveLoader>> Copy() const = 0;

  virtual EnclaveLoadConfig GetEnclaveLoadConfig() const = 0;
};

// Stores the mapping between signals and the enclave with a handler installed
// for that signal.
class EnclaveSignalDispatcher {
 public:
  static EnclaveSignalDispatcher *GetInstance();

  // Associates a signal with an enclave which registers a handler for it.
  // It's not supported for multiple enclaves to register the same signal. In
  // that case, the latter will overwrite the former.
  //
  // Returns the enclave client that previous registered |signum|, or nullptr if
  // no enclave has registered |signum| yet.
  const EnclaveClient *RegisterSignal(int signum, EnclaveClient *client)
      ABSL_LOCKS_EXCLUDED(signal_enclave_map_lock_);

  // Gets the enclave that registered a handler for |signum|.
  StatusOr<EnclaveClient *> GetClientForSignal(int signum) const
      ABSL_LOCKS_EXCLUDED(signal_enclave_map_lock_);

  // Deregisters all the signals registered by |client|.
  Status DeregisterAllSignalsForClient(EnclaveClient *client)
      ABSL_LOCKS_EXCLUDED(signal_enclave_map_lock_);

  // Looks for the enclave client that registered |signum|, and calls
  // EnterAndHandleSignal() with that enclave client. |signum|, |info| and
  // |ucontext| are passed into the enclave.
  Status EnterEnclaveAndHandleSignal(int signum, siginfo_t *info,
                                     void *ucontext);

 private:
  EnclaveSignalDispatcher() = default;  // Private to enforce singleton.
  EnclaveSignalDispatcher(EnclaveSignalDispatcher const &) = delete;
  void operator=(EnclaveSignalDispatcher const &) = delete;

  // Mapping of signal number to the enclave client that registered it.
  absl::flat_hash_map<int, EnclaveClient *> signal_to_client_map_
      ABSL_GUARDED_BY(signal_enclave_map_lock_);

  // A mutex that guards signal_to_client_map_ and client_to_signal_map_.
  mutable absl::Mutex signal_enclave_map_lock_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ENCLAVE_MANAGER_H_
