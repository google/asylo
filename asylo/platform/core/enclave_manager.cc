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

#include "asylo/platform/core/enclave_manager.h"

#include <stdint.h>
#include <sys/ucontext.h>
#include <time.h>

#include <thread>

#include "absl/strings/str_cat.h"

#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/platform/core/generic_enclave_client.h"
#include "asylo/platform/primitives/enclave_loader.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/fortanix_edp/loader.pb.h"
#include "asylo/platform/primitives/fortanix_edp/untrusted_edp.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// Returns the value of a monotonic clock as a number of nanoseconds.
int64_t MonotonicClock() {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
      << "Could not read monotonic clock.";
  return TimeSpecToNanoseconds(&ts);
}

// Returns the value of a realtime clock as a number of nanoseconds.
int64_t RealTimeClock() {
  struct timespec ts;
  CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0)
      << "Could not read realtime clock.";
  return TimeSpecToNanoseconds(&ts);
}

// Sleeps for a interval specified in nanoseconds.
void Sleep(int64_t nanoseconds) {
  struct timespec req;
  nanosleep(NanosecondsToTimeSpec(&req, nanoseconds), nullptr);
}

// Sleeps until a deadline, specified a value of MonotonicClock().
void WaitUntil(int64_t deadline) {
  int64_t delta;
  while ((delta = deadline - MonotonicClock()) > 0) {
    Sleep(delta);
  }
}

}  // namespace

absl::Mutex EnclaveManager::mu_;
bool EnclaveManager::configured_ = false;
EnclaveManagerOptions *EnclaveManager::options_ = nullptr;
EnclaveManager *EnclaveManager::instance_ = nullptr;

// By default, the options object holds an empty HostConfig proto.
EnclaveManagerOptions::EnclaveManagerOptions()
    : host_config_info_(absl::in_place_type_t<HostConfig>()) {}

EnclaveManagerOptions &
EnclaveManagerOptions::set_config_server_connection_attributes(
    absl::string_view address, absl::Duration timeout) {
  host_config_info_.emplace<ConfigServerConnectionAttributes>(address, timeout);
  return *this;
}

EnclaveManagerOptions &EnclaveManagerOptions::set_host_config(
    HostConfig config) {
  host_config_info_.emplace<HostConfig>(std::move(config));
  return *this;
}

StatusOr<absl::string_view> EnclaveManagerOptions::get_config_server_address()
    const {
  const ConfigServerConnectionAttributes *attributes =
      absl::get_if<ConfigServerConnectionAttributes>(&host_config_info_);
  if (!attributes) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Options object does not hold config-server address");
  }
  return attributes->server_address;
}

StatusOr<absl::Duration>
EnclaveManagerOptions::get_config_server_connection_timeout() const {
  const ConfigServerConnectionAttributes *attributes =
      absl::get_if<ConfigServerConnectionAttributes>(&host_config_info_);
  if (!attributes) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Options object does not hold server-connection timeout");
  }
  return attributes->connection_timeout;
}

StatusOr<HostConfig> EnclaveManagerOptions::get_host_config() const {
  const HostConfig *config = absl::get_if<HostConfig>(&host_config_info_);
  if (!config) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Options object does not contain a HostConfig");
  }
  return *config;
}

bool EnclaveManagerOptions::holds_host_config() const {
  return absl::holds_alternative<HostConfig>(host_config_info_);
}

HostConfig EnclaveManager::GetHostConfig() {
  if (options_->holds_host_config()) {
    StatusOr<HostConfig> config_result = options_->get_host_config();
    if (!config_result.ok()) {
      LOG(ERROR) << config_result.status();
      return HostConfig();
    }
    return config_result.ValueOrDie();
  }

  HostConfig config;
  LOG(ERROR) << "Not implemented";
  return config;
}

EnclaveManager::EnclaveManager() : host_config_(GetHostConfig()) {
  Status rc = shared_resource_manager_.RegisterUnmanagedResource(
      SharedName::Address("clock_monotonic"), &clock_monotonic_);
  if (!rc.ok()) {
    LOG(FATAL) << "Could not register monotonic clock resource.";
  }

  rc = shared_resource_manager_.RegisterUnmanagedResource(
      SharedName::Address("clock_realtime"), &clock_realtime_);
  if (!rc.ok()) {
    LOG(FATAL) << "Could not register realtime clock resource.";
  }
}

Status EnclaveManager::DestroyEnclave(EnclaveClient *client,
                                      const EnclaveFinal &final_input,
                                      bool skip_finalize) {
  if (!client) {
    return Status::OkStatus();
  }

  Status finalize_status;
  if (!skip_finalize) {
    finalize_status = client->EnterAndFinalize(final_input);
  }

  Status status = client->DestroyEnclave();
  LOG_IF(ERROR, !status.ok()) << "Client's DestroyEnclave failed: " << status;

  absl::WriterMutexLock lock(&client_table_lock_);
  const auto &name = name_by_client_[client];
  client_by_name_.erase(name);
  name_by_client_.erase(client);
  load_config_by_client_.erase(client);

  return finalize_status;
}

EnclaveClient *EnclaveManager::GetClient(absl::string_view name) const {
  absl::ReaderMutexLock lock(&client_table_lock_);
  auto it = client_by_name_.find(name);
  if (it == client_by_name_.end()) {
    return nullptr;
  } else {
    return it->second.get();
  }
}

const absl::string_view EnclaveManager::GetName(
    const EnclaveClient *client) const {
  absl::ReaderMutexLock lock(&client_table_lock_);
  auto it = name_by_client_.find(client);
  if (it == name_by_client_.end()) {
    return absl::string_view();
  } else {
    return it->second;
  }
}

EnclaveLoadConfig EnclaveManager::GetLoadConfigFromClient(
    EnclaveClient *client) {
  absl::ReaderMutexLock lock(&client_table_lock_);
  if (!client ||
      load_config_by_client_.find(client) == load_config_by_client_.end()) {
    EnclaveLoadConfig config;
    return config;
  }
  return load_config_by_client_[client];
}

Status EnclaveManager::Configure(const EnclaveManagerOptions &options) {
  absl::MutexLock lock(&mu_);

  if (instance_) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Cannot configure the enclave manager after an instance has "
                  "been created");
  }

  delete options_;
  options_ = new EnclaveManagerOptions(options);
  configured_ = true;
  return Status::OkStatus();
}

StatusOr<EnclaveManager *> EnclaveManager::Instance() {
  absl::MutexLock lock(&mu_);

  if (instance_) {
    return instance_;
  }

  if (!configured_) {
    return Status(
        error::GoogleError::FAILED_PRECONDITION,
        "Cannot create enclave manager instance before it is configured");
  }

  instance_ = new EnclaveManager();
  if (!instance_) {
    return Status(error::GoogleError::RESOURCE_EXHAUSTED,
                  "Could not create an instance of the enclave manager");
  }

  return instance_;
}

Status EnclaveManager::LoadEnclave(absl::string_view name,
                                   const EnclaveLoader &loader,
                                   void *base_address,
                                   const size_t enclave_size) {
  EnclaveLoadConfig load_config = loader.GetEnclaveLoadConfig();
  load_config.set_name(name.data(), name.size());
  if (load_config.HasExtension(sgx_load_config)) {
    if (!base_address && enclave_size != 0) {
      if (load_config.HasExtension(sgx_load_config)) {
        SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
        // Enclave load initiated by implementation of fork.
        SgxLoadConfig::ForkConfig fork_config;
        fork_config.set_base_address(reinterpret_cast<uint64_t>(base_address));
        fork_config.set_enclave_size(enclave_size);
        *sgx_config.mutable_fork_config() = fork_config;
      }
    }
    return LoadEnclave(load_config);
  } else if (load_config.HasExtension(fortanix_edp_load_config)) {
    return LoadEnclave(load_config);
  } else {
    return LoadFakeEnclave(name, loader,
                           CreateDefaultEnclaveConfig(host_config_),
                           base_address, enclave_size);
  }
}

Status EnclaveManager::LoadEnclave(absl::string_view name,
                                   const EnclaveLoader &loader,
                                   EnclaveConfig config, void *base_address,
                                   const size_t enclave_size) {
  EnclaveLoadConfig load_config = loader.GetEnclaveLoadConfig();
  load_config.set_name(name.data(), name.size());
  if (load_config.HasExtension(sgx_load_config)) {
    *load_config.mutable_config() = config;
    if (!base_address && enclave_size != 0) {
      if (load_config.HasExtension(sgx_load_config)) {
        SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
        // Enclave load initiated by implementation of fork.
        SgxLoadConfig::ForkConfig fork_config;
        fork_config.set_base_address(reinterpret_cast<uint64_t>(base_address));
        fork_config.set_enclave_size(enclave_size);
        *sgx_config.mutable_fork_config() = fork_config;
      }
    }
    return LoadEnclave(load_config);
  } else if (load_config.HasExtension(fortanix_edp_load_config)) {
    return LoadEnclave(load_config);
  } else {
    EnclaveConfig sanitized_config = std::move(config);
    SetEnclaveConfigDefaults(host_config_, &sanitized_config);
    return LoadFakeEnclave(name, loader, sanitized_config, base_address,
                           enclave_size);
  }
}

Status EnclaveManager::LoadFakeEnclave(absl::string_view name,
                                       const EnclaveLoader &loader,
                                       const EnclaveConfig &config,
                                       void *base_address,
                                       const size_t enclave_size) {
  // Check whether a client with this name already exists.
  {
    absl::ReaderMutexLock lock(&client_table_lock_);
    if (client_by_name_.find(name) != client_by_name_.end()) {
      Status status(error::GoogleError::ALREADY_EXISTS,
                    absl::StrCat("Name already exists: ", name));
      LOG(ERROR) << "LoadEnclave failed: " << status;
      return status;
    }
  }

  // Attempt to load the enclave.
  StatusOr<std::unique_ptr<EnclaveClient>> result =
      loader.LoadEnclave(name, base_address, enclave_size, config);
  if (!result.ok()) {
    LOG(ERROR) << "LoadEnclave failed: " << result.status();
    return result.status();
  }

  // Add the client to the lookup tables.
  EnclaveClient *client = result.ValueOrDie().get();
  {
    absl::WriterMutexLock lock(&client_table_lock_);
    client_by_name_.emplace(name, std::move(result).ValueOrDie());
    name_by_client_.emplace(client, name);
  }

  Status status = client->EnterAndInitialize(config);
  // If initialization fails, don't keep the enclave registered. GetClient will
  // return a nullptr rather than an enclave in a bad state.
  if (!status.ok()) {
    Status destroy_status = client->DestroyEnclave();
    if (!destroy_status.ok()) {
      LOG(ERROR) << "DestroyEnclave failed after EnterAndInitialize failure: "
                 << destroy_status;
    }
    {
      absl::WriterMutexLock lock(&client_table_lock_);
      client_by_name_.erase(name);
      name_by_client_.erase(client);
    }
  }
  return status;
}

Status EnclaveManager::LoadEnclave(const EnclaveLoadConfig &load_config) {
  EnclaveConfig config;
  if (load_config.has_config()) {
    config = load_config.config();
    SetEnclaveConfigDefaults(host_config_, &config);
  } else {
    config = CreateDefaultEnclaveConfig(host_config_);
  }

  void *base_address = nullptr;
  if (load_config.HasExtension(sgx_load_config)) {
    SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
    primitives::SgxEnclaveClient::SetForkedEnclaveLoader(
        LoadEnclaveInChildProcess);
    if (sgx_config.has_fork_config()) {
      SgxLoadConfig::ForkConfig fork_config = sgx_config.fork_config();
      base_address = reinterpret_cast<void *>(fork_config.base_address());
    }
  }

  std::string name = load_config.name();
  if (config.enable_fork() && base_address) {
    // If fork is enabled and a base address is provided, it is now loading an
    // enclave in the child process. Remove the reference in the enclave table
    // that points to the enclave in the parent process.
    RemoveEnclaveReference(name);
  }
  // Check whether a client with this name already exists.
  {
    absl::ReaderMutexLock lock(&client_table_lock_);
    if (client_by_name_.find(name) != client_by_name_.end()) {
      Status status(error::GoogleError::ALREADY_EXISTS,
                    absl::StrCat("Name already exists: ", name));
      LOG(ERROR) << "LoadEnclave failed: " << status;
      return status;
    }
  }

  // Attempt to load the enclave.
  auto primitive_client =
      asylo::primitives::LoadEnclave(load_config).ValueOrDie();
  StatusOr<std::unique_ptr<EnclaveClient>> result =
      GenericEnclaveClient::Create(name, primitive_client);
  if (!result.ok()) {
    LOG(ERROR) << "LoadEnclave failed: " << result.status();
    return result.status();
  }

  // Add the client to the lookup tables.
  EnclaveClient *client = result.ValueOrDie().get();
  {
    absl::WriterMutexLock lock(&client_table_lock_);
    client_by_name_.emplace(name, std::move(result).ValueOrDie());
    name_by_client_.emplace(client, name);

    if (config.enable_fork()) {
      load_config_by_client_.emplace(client, load_config);
    }
  }

  Status status = client->EnterAndInitialize(config);
  // If initialization fails, don't keep the enclave registered. GetClient will
  // return a nullptr rather than an enclave in a bad state.
  if (!status.ok()) {
    Status destroy_status = client->DestroyEnclave();
    if (!destroy_status.ok()) {
      LOG(ERROR) << "DestroyEnclave failed after EnterAndInitialize failure: "
                 << destroy_status;
    }
    {
      absl::WriterMutexLock lock(&client_table_lock_);
      client_by_name_.erase(name);
      name_by_client_.erase(client);
      load_config_by_client_.erase(client);
    }
  }
  return status;
}

void EnclaveManager::RemoveEnclaveReference(absl::string_view name) {
  absl::WriterMutexLock lock(&client_table_lock_);
  EnclaveClient *client = client_by_name_[name].get();
  client_by_name_.erase(name);
  name_by_client_.erase(client);
}

primitives::Client *LoadEnclaveInChildProcess(absl::string_view enclave_name,
                                              void *enclave_base_address,
                                              size_t enclave_size) {
  auto manager_result = EnclaveManager::Instance();
  if (!manager_result.ok()) {
    errno = EFAULT;
    return nullptr;
  }
  EnclaveManager *manager = manager_result.ValueOrDie();
  auto *client =
      dynamic_cast<GenericEnclaveClient *>(manager->GetClient(enclave_name));
  EnclaveLoadConfig load_config = manager->GetLoadConfigFromClient(client);

  // Fork is currently only supported for local SGX. The child enclave should
  // use the same loader as the parent. It loads by an SGX loader or SGX
  // embedded loader depending on the parent enclave.
  if (!load_config.HasExtension(sgx_load_config)) {
    LOG(ERROR) << "Failed to get the loader for the enclave to fork.";
    errno = EFAULT;
    return nullptr;
  }

  // Load an enclave at the same virtual space as the parent.
  load_config.set_name(enclave_name.data(), enclave_name.size());
  SgxLoadConfig sgx_config = load_config.GetExtension(sgx_load_config);
  SgxLoadConfig::ForkConfig fork_config;
  fork_config.set_base_address(
      reinterpret_cast<uint64_t>(enclave_base_address));
  fork_config.set_enclave_size(enclave_size);
  *sgx_config.mutable_fork_config() = fork_config;
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;
  auto status = manager->LoadEnclave(load_config);
  if (!status.ok()) {
    LOG(ERROR) << "LoadEnclaveInChildProcess: Load new enclave failed:"
               << status;
    errno = ENOMEM;
    return nullptr;
  }

  // Fetch the client corresponding to enclave_name, which should now point to
  // the child enclave.
  client = dynamic_cast<asylo::GenericEnclaveClient *>(
      manager->GetClient(enclave_name));
  auto primitive_client = client->GetPrimitiveClient();
  return primitive_client.get();
}

};  // namespace asylo
