/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/platform/core/trusted_application.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <cerrno>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/identity/init.h"
#include "asylo/platform/arch/include/trusted/fork.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/arch/include/trusted/time.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/core/shared_name_kind.h"
#include "asylo/platform/core/trusted_global_state.h"
#include "asylo/platform/posix/io/io_manager.h"
#include "asylo/platform/posix/io/native_paths.h"
#include "asylo/platform/posix/io/random_devices.h"
#include "asylo/platform/posix/signal/signal_manager.h"
#include "asylo/platform/posix/threading/thread_manager.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

using EnclaveState = ::asylo::TrustedApplication::State;
using google::protobuf::RepeatedPtrField;

namespace asylo {
namespace {

void LogError(const Status &status) {
  EnclaveState state = GetApplicationInstance()->GetState();
  if (state < EnclaveState::kUserInitializing) {
    // LOG() is unavailable here because the I/O subsystem has not yet been
    // initialized.
    enc_untrusted_puts(status.ToString().c_str());
  } else {
    LOG(ERROR) << status;
  }
}

// StatusSerializer can be used to serialize a given proto2 message to an
// untrusted buffer.
//
// OutputProto must be a proto2 message type.
template <class OutputProto>
class StatusSerializer {
 public:
  // Creates a new StatusSerializer that saves Status objects to |status_proto|,
  // which is a nested message within |output_proto|. StatusSerializer does not
  // take ownership of any of the input pointers. Input pointers must remain
  // valid for the lifetime of the StatusSerializer.
  StatusSerializer(const OutputProto *output_proto, StatusProto *status_proto,
                   char **output, size_t *output_len)
      : output_proto_{output_proto},
        status_proto_{status_proto},
        output_{output},
        output_len_{output_len} {}

  // Creates a new StatusSerializer that saves Status objects to |status_proto|.
  // StatusSerializer does not take ownership of any of the input pointers.
  // Input pointers must remain valid for the lifetime of the StatusSerializer.
  StatusSerializer(char **output, size_t *output_len)
      : output_proto_{&proto},
        status_proto_{&proto},
        output_{output},
        output_len_{output_len} {}

  // Saves the given |status| into the StatusSerializer's status_proto_. Then
  // serializes its output_proto_ into a buffer. On success 0 is returned, else
  // 1 is returned and the StatusSerializer logs the error.
  int Serialize(const Status &status) {
    status.SaveTo(status_proto_);

    // Serialize to a trusted buffer instead of an untrusted buffer because the
    // serialization routine may rely on read backs for correctness.
    *output_len_ = output_proto_->ByteSize();
    std::unique_ptr<char[]> trusted_output(new char[*output_len_]);
    if (!output_proto_->SerializeToArray(trusted_output.get(), *output_len_)) {
      *output_ = nullptr;
      *output_len_ = 0;
      LogError(status);
      return 1;
    }
    *output_ = reinterpret_cast<char *>(enc_untrusted_malloc(*output_len_));
    memcpy(*output_, trusted_output.get(), *output_len_);
    return 0;
  }

 private:
  OutputProto proto;
  const OutputProto *output_proto_;
  StatusProto *status_proto_;
  char **output_;
  size_t *output_len_;
};

}  // namespace

Status TrustedApplication::VerifyAndSetState(const EnclaveState &expected_state,
                                             const EnclaveState &new_state) {
  absl::MutexLock lock(&mutex_);
  if (enclave_state_ != expected_state) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  ::absl::StrCat("Enclave is in state: ", enclave_state_,
                                 " expected state: ", expected_state));
  }
  enclave_state_ = new_state;
  return Status::OkStatus();
}

EnclaveState TrustedApplication::GetState() {
  absl::MutexLock lock(&mutex_);
  return enclave_state_;
}

void TrustedApplication::SetState(const EnclaveState &state) {
  absl::MutexLock lock(&mutex_);
  enclave_state_ = state;
}

Status VerifyOutputArguments(char **output, size_t *output_len) {
  if (!output || !output_len) {
    Status status =
        Status(error::GoogleError::INVALID_ARGUMENT,
               "Invalid input parameter passed to __asylo_user...()");
    LogError(status);
    return status;
  }
  return Status::OkStatus();
}

// Application instance returned by BuildTrustedApplication.
static TrustedApplication *global_trusted_application = nullptr;

// A mutex that avoids race condition when getting |global_trusted_application|.
static absl::Mutex get_application_lock;

// Initialize IO subsystem.
static void InitializeIO(const EnclaveConfig &config);

TrustedApplication *GetApplicationInstance() {
  absl::MutexLock lock(&get_application_lock);
  if (!global_trusted_application) {
    global_trusted_application = BuildTrustedApplication();
  }
  return global_trusted_application;
}

Status InitializeEnvironmentVariables(
    const RepeatedPtrField<EnvironmentVariable> &variables) {
  for (const auto &variable : variables) {
    if (!variable.has_name() || !variable.has_value()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Environment variables should set both name and value "
                    "fields");
    }
    setenv(variable.name().c_str(), variable.value().c_str(), /*overwrite=*/0);
  }
  return Status::OkStatus();
}

Status TrustedApplication::InitializeInternal(const EnclaveConfig &config) {
  InitializeIO(config);
  Status status =
      InitializeEnvironmentVariables(config.environment_variables());
  const char *log_directory = config.logging_config().log_directory().c_str();
  int vlog_level = config.logging_config().vlog_level();
  if(!InitLogging(log_directory, GetEnclaveName().c_str(), vlog_level)) {
    fprintf(stderr, "Initialization of enclave logging failed\n");
  }
  if (!status.ok()) {
    LOG(WARNING) << "Initialization of enclave environment variables failed: "
                 << status;
  }
  SetEnclaveConfig(config);
  // This call can fail, but it should not stop the enclave from running.
  status = InitializeEnclaveAssertionAuthorities(
      config.enclave_assertion_authority_configs().begin(),
      config.enclave_assertion_authority_configs().end());
  if (!status.ok()) {
    LOG(WARNING) << "Initialization of enclave assertion authorities failed: "
                 << status;
  }

  ASYLO_RETURN_IF_ERROR(VerifyAndSetState(EnclaveState::kInternalInitializing,
                                          EnclaveState::kUserInitializing));
  return Initialize(config);
}

void InitializeIO(const EnclaveConfig &config) {
  auto &io_manager = io::IOManager::GetInstance();

  // Register host file descriptors as stdin, stdout, and stderr. The order of
  // initialization is significant since we need to match the convention that
  // these refer to descriptors 0, 1, and 2 respectively.
  if (config.stdin_fd() >= 0) {
    io_manager.RegisterHostFileDescriptor(config.stdin_fd());
  }
  if (config.stdout_fd() >= 0) {
    io_manager.RegisterHostFileDescriptor(config.stdout_fd());
  }
  if (config.stderr_fd() >= 0) {
    io_manager.RegisterHostFileDescriptor(config.stderr_fd());
  }

  // Register handler for / so paths without other handlers are forwarded on to
  // the host system. Paths are registered without the trailing slash, so an
  // empty string is used.
  io_manager.RegisterVirtualPathHandler(
      "", ::absl::make_unique<io::NativePathHandler>());

  // Register handlers for /dev/random and /dev/urandom so they can be opened
  // and read like regular files without exiting the enclave.
  io_manager.RegisterVirtualPathHandler(
      RandomPathHandler::kRandomPath, ::absl::make_unique<RandomPathHandler>());
  io_manager.RegisterVirtualPathHandler(
      RandomPathHandler::kURandomPath,
      ::absl::make_unique<RandomPathHandler>());

  // Set the current working directory so that relative paths can be handled.
  io_manager.SetCurrentWorkingDirectory(config.current_working_directory());
}

// Asylo enclave entry points.
//
// See asylo/platform/arch/include/trusted/entry_points.h for detailed
// documentation for each function.
extern "C" {

int __asylo_user_init(const char *name, const char *config, size_t config_len,
                      char **output, size_t *output_len) {
  Status status = VerifyOutputArguments(output, output_len);
  if (!status.ok()) {
    return 1;
  }

  StatusSerializer<StatusProto> status_serializer(output, output_len);

  EnclaveConfig enclave_config;
  if (!enclave_config.ParseFromArray(config, config_len)) {
    status = Status(error::GoogleError::INVALID_ARGUMENT,
                    "Failed to parse EnclaveConfig");
    return status_serializer.Serialize(status);
  }

  TrustedApplication *trusted_application = GetApplicationInstance();
  status = trusted_application->VerifyAndSetState(
      EnclaveState::kUninitialized, EnclaveState::kInternalInitializing);
  if (!status.ok()) {
    return status_serializer.Serialize(status);
  }

  SetEnclaveName(name);
  // Invoke the enclave entry-point.
  status = trusted_application->InitializeInternal(enclave_config);
  if (!status.ok()) {
    trusted_application->SetState(EnclaveState::kUninitialized);
    return status_serializer.Serialize(status);
  }

  trusted_application->SetState(EnclaveState::kRunning);
  return status_serializer.Serialize(status);
}

int __asylo_user_run(const char *input, size_t input_len, char **output,
                     size_t *output_len) {
  Status status = VerifyOutputArguments(output, output_len);
  if (!status.ok()) {
    return 1;
  }

  EnclaveOutput enclave_output;
  StatusSerializer<EnclaveOutput> status_serializer(
      &enclave_output, enclave_output.mutable_status(), output, output_len);

  EnclaveInput enclave_input;
  if (!enclave_input.ParseFromArray(input, input_len)) {
    status = Status(error::GoogleError::INVALID_ARGUMENT,
                    "Failed to parse EnclaveInput");
    return status_serializer.Serialize(status);
  }

  TrustedApplication *trusted_application = GetApplicationInstance();
  if (trusted_application->GetState() != EnclaveState::kRunning) {
    status = Status(error::GoogleError::FAILED_PRECONDITION,
                    "Enclave not in state RUNNING");
    return status_serializer.Serialize(status);
  }

  // Invoke the enclave entry-point.
  status = trusted_application->Run(enclave_input, &enclave_output);
  return status_serializer.Serialize(status);
}

int __asylo_user_fini(const char *input, size_t input_len, char **output,
                      size_t *output_len) {
  Status status = VerifyOutputArguments(output, output_len);
  if (!status.ok()) {
    return 1;
  }

  StatusSerializer<StatusProto> status_serializer(output, output_len);

  asylo::EnclaveFinal enclave_final;
  if (!enclave_final.ParseFromArray(input, input_len)) {
    status = Status(error::GoogleError::INVALID_ARGUMENT,
                    "Failed to parse EnclaveFinal");
    return status_serializer.Serialize(status);
  }

  TrustedApplication *trusted_application = GetApplicationInstance();
  status = trusted_application->VerifyAndSetState(EnclaveState::kRunning,
                                                  EnclaveState::kFinalizing);
  if (!status.ok()) {
    return status_serializer.Serialize(status);
  }

  // Invoke the enclave entry-point.
  status = trusted_application->Finalize(enclave_final);
  if (!status.ok()) {
    trusted_application->SetState(EnclaveState::kRunning);
    return status_serializer.Serialize(status);
  }

  trusted_application->SetState(EnclaveState::kFinalized);
  return status_serializer.Serialize(status);
}

int __asylo_threading_donate() {
  TrustedApplication *trusted_application = GetApplicationInstance();
  EnclaveState current_state = trusted_application->GetState();
  if (current_state < EnclaveState::kUserInitializing ||
      current_state > EnclaveState::kFinalizing) {
    Status status = Status(error::GoogleError::FAILED_PRECONDITION,
                           "Enclave ThreadManager has not been initialized");
    LOG(ERROR) << status;
    return EPERM;
  }

  ThreadManager *thread_manager = ThreadManager::GetInstance();
  return thread_manager->StartThread();
}

int __asylo_handle_signal(const char *input, size_t input_len) {
  asylo::EnclaveSignal signal;
  if (!signal.ParseFromArray(input, input_len)) {
    return 1;
  }
  TrustedApplication *trusted_application = GetApplicationInstance();
  EnclaveState current_state = trusted_application->GetState();
  if (current_state < EnclaveState::kRunning ||
      current_state > EnclaveState::kFinalizing) {
    return 2;
  }
  int signum = FromBridgeSignal(signal.signum());
  if (signum < 0) {
    return 1;
  }
  siginfo_t info;
  info.si_signo = signum;
  info.si_code = signal.code();
  ucontext_t ucontext;
  for (int greg_index = 0;
       greg_index < NGREG && greg_index < signal.gregs_size(); ++greg_index) {
    ucontext.uc_mcontext.gregs[greg_index] =
        static_cast<greg_t>(signal.gregs(greg_index));
  }
  SignalManager *signal_manager = SignalManager::GetInstance();
  const sigset_t mask = signal_manager->GetSignalMask();

  // If the signal is blocked and still passed into the enclave. The signal
  // masks inside the enclave is out of sync with the untrusted signal mask.
  if (sigismember(&mask, signum)) {
    return -1;
  }
  if (!signal_manager->HandleSignal(signum, &info, &ucontext).ok()) {
    return 1;
  }
  return 0;
}

int __asylo_take_snapshot(char **output, size_t *output_len) {
  Status status = VerifyOutputArguments(output, output_len);
  if (!status.ok()) {
    return 1;
  }
  EnclaveOutput enclave_output;
  StatusSerializer<EnclaveOutput> status_serializer(
      &enclave_output, enclave_output.mutable_status(), output, output_len);

#ifndef INSECURE_DEBUG_FORK_ENABLED
  status = Status(error::GoogleError::FAILED_PRECONDITION,
                  "Insecure fork not enabled");
  return status_serializer.Serialize(status);
#endif  // INSECURE_DEBUG_FORK_ENABLED

  TrustedApplication *trusted_application = GetApplicationInstance();
  if (trusted_application->GetState() != EnclaveState::kRunning) {
    status = Status(error::GoogleError::FAILED_PRECONDITION,
                    "Enclave not in state RUNNING");
    return status_serializer.Serialize(status);
  }

  status = TakeSnapshotForFork(enclave_output.mutable_snapshot_layout());
  return status_serializer.Serialize(status);
}

int __asylo_restore(const char *input, size_t input_len, char **output,
                    size_t *output_len) {
  Status status = VerifyOutputArguments(output, output_len);
  if (!status.ok()) {
    return 1;
  }

  StatusSerializer<StatusProto> status_serializer(output, output_len);

#ifndef INSECURE_DEBUG_FORK_ENABLED
  status = Status(error::GoogleError::FAILED_PRECONDITION,
                  "Insecure fork not enabled");
  return status_serializer.Serialize(status);
#endif  // INSECURE_DEBUG_FORK_ENABLED

  asylo::SnapshotLayout snapshot_layout;
  if (!snapshot_layout.ParseFromArray(input, input_len)) {
    status = Status(error::GoogleError::INVALID_ARGUMENT,
                    "Failed to parse SnapshotLayout");
    return status_serializer.Serialize(status);
  }

  TrustedApplication *trusted_application = GetApplicationInstance();
  if (trusted_application->GetState() != EnclaveState::kRunning) {
    status = Status(error::GoogleError::FAILED_PRECONDITION,
                    "Enclave not in state RUNNING");
    return status_serializer.Serialize(status);
  }

  status = RestoreForFork(snapshot_layout);
  return status_serializer.Serialize(status);
}

}  // extern "C"

}  // namespace asylo
