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

#include <signal.h>
#include <stdint.h>
#include <sys/ucontext.h>
#include <time.h>
#include <thread>

#include "absl/strings/str_cat.h"

#include "asylo/util/logging.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/util/status_macros.h"

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

void donate(asylo::EnclaveClient *client) {
  Status status = client->EnterAndDonateThread();
  if (!status.ok()) {
    LOG(ERROR) << "EnterAndDonateThread() failed: " << status;
  }
}

// By default, the options object holds an empty HostConfig proto.
EnclaveManagerOptions::EnclaveManagerOptions()
    : host_config_info_(absl::in_place_type_t<HostConfig>()) {}

EnclaveManagerOptions &
EnclaveManagerOptions::set_config_server_connection_attributes(
    std::string address, absl::Duration timeout) {
  host_config_info_.emplace<ConfigServerConnectionAttributes>(
      std::move(address), timeout);
  return *this;
}

EnclaveManagerOptions &EnclaveManagerOptions::set_host_config(
    HostConfig config) {
  host_config_info_.emplace<HostConfig>(std::move(config));
  return *this;
}

StatusOr<std::string> EnclaveManagerOptions::get_config_server_address() const {
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

  SpawnWorkerThread();
}

Status EnclaveManager::DestroyEnclave(EnclaveClient *client,
                                      const EnclaveFinal &final_input,
                                      bool skip_finalize) {
  if (!client) {
    return Status::OkStatus();
  }

  if (!skip_finalize) {
    ASYLO_RETURN_IF_ERROR(client->EnterAndFinalize(final_input));
  }

  ASYLO_RETURN_IF_ERROR(client->DestroyEnclave());
  const Status status =
      EnclaveSignalDispatcher::GetInstance()->DeregisterAllSignalsForClient(
          client);
  const auto &name = name_by_client_[client];
  client_by_name_.erase(name);
  name_by_client_.erase(client);
  loader_by_client_.erase(client);

  return status;
}

Status EnclaveManager::EnterAndTakeSnapshot(EnclaveClient *client,
                                            SnapshotLayout *snapshot_layout) {
  if (!client) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Enclave client does not exist");
  }
  return client->EnterAndTakeSnapshot(snapshot_layout);
}

Status EnclaveManager::EnterAndRestore(EnclaveClient *client,
                                       const SnapshotLayout &snapshot_layout) {
  if (!client) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Enclave client does not exist");
  }
  return client->EnterAndRestore(snapshot_layout);
}

EnclaveClient *EnclaveManager::GetClient(const std::string &name) const {
  auto it = client_by_name_.find(name);
  if (it == client_by_name_.end()) {
    return nullptr;
  } else {
    return it->second.get();
  }
}

const std::string EnclaveManager::GetName(const EnclaveClient *client) const {
  auto it = name_by_client_.find(client);
  if (it == name_by_client_.end()) {
    return "";
  } else {
    return it->second;
  }
}

EnclaveLoader *EnclaveManager::GetLoaderFromClient(EnclaveClient *client) {
  if (!client || loader_by_client_.find(client) == loader_by_client_.end()) {
    return nullptr;
  }
  return loader_by_client_[client].get();
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

Status EnclaveManager::LoadEnclave(const std::string &name,
                                   const EnclaveLoader &loader,
                                   void *base_address) {
  return LoadEnclaveInternal(
      name, loader, CreateDefaultEnclaveConfig(host_config_), base_address);
}

Status EnclaveManager::LoadEnclave(const std::string &name,
                                   const EnclaveLoader &loader,
                                   EnclaveConfig config, void *base_address) {
  EnclaveConfig sanitized_config = std::move(config);
  SetEnclaveConfigDefaults(host_config_, &sanitized_config);
  return LoadEnclaveInternal(name, loader, sanitized_config, base_address);
}

Status EnclaveManager::LoadEnclaveInternal(const std::string &name,
                                           const EnclaveLoader &loader,
                                           const EnclaveConfig &config,
                                           void *base_address) {
  if (config.enable_fork() && base_address) {
    // If fork is enabled and a base address is provided, it is now loading an
    // enclave in the child process. Remove the reference in the enclave table
    // that points to the enclave in the parent process.
    RemoveEnclaveReference(name);
  }
  // Check whether a client with this name already exists.
  if (client_by_name_.find(name) != client_by_name_.end()) {
    Status status(error::GoogleError::ALREADY_EXISTS,
                  "Name already exists: " + name);
    LOG(ERROR) << "LoadEnclave failed: " << status;
    return status;
  }

  // Attempt to load the enclave.
  StatusOr<std::unique_ptr<EnclaveClient>> result =
      loader.LoadEnclave(name, base_address, config);
  if (!result.ok()) {
    LOG(ERROR) << "LoadEnclave failed: " << result.status();
    return result.status();
  }

  // Add the client to the lookup tables.
  EnclaveClient *client = result.ValueOrDie().get();
  client_by_name_.emplace(name, std::move(result).ValueOrDie());
  name_by_client_.emplace(client, name);

  if (config.enable_fork()) {
    StatusOr<std::unique_ptr<EnclaveLoader>> loader_result = loader.Copy();
    if (!loader_result.ok()) {
      return loader_result.status();
    }
    loader_by_client_.emplace(client, std::move(loader_result.ValueOrDie()));
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
    client_by_name_.erase(name);
    name_by_client_.erase(client);
    loader_by_client_.erase(client);
  }
  return status;
}

void EnclaveManager::RemoveEnclaveReference(const std::string &name) {
  EnclaveClient *client = client_by_name_[name].get();
  client_by_name_.erase(name);
  name_by_client_.erase(client);
  loader_by_client_.erase(client);
}

void EnclaveManager::SpawnWorkerThread() {
  // Tick() here is to prevent a race condition between the WorkLoop thread
  // initializing and other threads accressing the resources.
  Tick();
  std::thread worker([this] { WorkerLoop(); });
  worker.detach();
}

void EnclaveManager::Tick() {
  clock_monotonic_ = MonotonicClock();
  clock_realtime_ = RealTimeClock();
}

void EnclaveManager::WorkerLoop() {
  // Tick each 70us ~ 14.29kHz
  constexpr int64_t kClockPeriod = INT64_C(70000);
  int64_t next_tick = MonotonicClock();
  while (true) {
    WaitUntil(next_tick);
    Tick();
    next_tick += kClockPeriod;
  }
}

EnclaveSignalDispatcher *EnclaveSignalDispatcher::GetInstance() {
  static EnclaveSignalDispatcher *instance = new EnclaveSignalDispatcher();
  return instance;
}

StatusOr<EnclaveClient *> EnclaveSignalDispatcher::GetClientForSignal(
    int signum) const {
  absl::MutexLock lock(&signal_enclave_map_lock_);
  auto it = signal_to_client_map_.find(signum);
  if (it == signal_to_client_map_.end()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("No enclave has registered signal: ", signum));
  }
  return it->second;
}

const EnclaveClient *EnclaveSignalDispatcher::RegisterSignal(
    int signum, EnclaveClient *client) {
  // Block all signals when registering a signal handler to avoid deadlock.
  sigset_t mask, oldmask;
  sigfillset(&mask);
  sigprocmask(SIG_SETMASK, &mask, &oldmask);
  EnclaveClient *old_client = nullptr;
  {
    absl::MutexLock lock(&signal_enclave_map_lock_);
    // If this signal is registered by another enclave, deregister it first.
    auto client_iterator = signal_to_client_map_.find(signum);
    if (client_iterator != signal_to_client_map_.end()) {
      old_client = client_iterator->second;
    }
    signal_to_client_map_[signum] = client;
  }
  // Set the signal mask back to the original one to unblock the signals.
  sigprocmask(SIG_SETMASK, &oldmask, nullptr);
  return old_client;
}

Status EnclaveSignalDispatcher::DeregisterAllSignalsForClient(
    EnclaveClient *client) {
  sigset_t mask, oldmask;
  sigfillset(&mask);
  sigprocmask(SIG_SETMASK, &mask, &oldmask);
  Status status = Status::OkStatus();
  {
    absl::MutexLock lock(&signal_enclave_map_lock_);
    // If this enclave has registered any signals, deregister them and set the
    // signal handler to the default one.
    for (auto iterator = signal_to_client_map_.begin();
         iterator != signal_to_client_map_.end();) {
      if (iterator->second == client) {
        if (signal(iterator->first, SIG_DFL) == SIG_ERR) {
          status = Status(
              error::GoogleError::INVALID_ARGUMENT,
              absl::StrCat(
                  "Failed to deregister one or more handlers for signal: ",
                  iterator->first));
        }
        auto saved_iterator = iterator;
        ++iterator;
        signal_to_client_map_.erase(saved_iterator);
      } else {
        ++iterator;
      }
    }
  }
  sigprocmask(SIG_SETMASK, &oldmask, nullptr);
  return status;
}

Status EnclaveSignalDispatcher::EnterEnclaveAndHandleSignal(int signum,
                                                            siginfo_t *info,
                                                            void *ucontext) {
  EnclaveClient *client;
  ASYLO_ASSIGN_OR_RETURN(client, GetClientForSignal(signum));
  EnclaveSignal enclave_signal;
  enclave_signal.set_signum(signum);
  enclave_signal.set_code(info->si_code);
  enclave_signal.clear_gregs();
  ucontext_t *uc = reinterpret_cast<ucontext_t *>(ucontext);
  for (int greg_index = 0; greg_index < NGREG; ++greg_index) {
    enclave_signal.add_gregs(
        static_cast<uint64_t>(uc->uc_mcontext.gregs[greg_index]));
  }
  return client->EnterAndHandleSignal(enclave_signal);
}

};  // namespace asylo

extern "C" {

int __asylo_donate_thread(const char *name) {
  auto manager_result = ::asylo::EnclaveManager::Instance();
  if (!manager_result.ok()) {
    LOG(ERROR) << manager_result.status();
    return -1;
  }
  asylo::EnclaveClient *client = manager_result.ValueOrDie()->GetClient(name);
  if (!client) {
    return -1;
  }

  std::thread thread(asylo::donate, client);
  thread.detach();

  return 0;
}

}  // extern "C"
