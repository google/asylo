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

#include <sys/ucontext.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/identity/init.h"
#include "asylo/platform/common/enclave_state.h"
#include "asylo/platform/core/entry_selectors.h"
#include "asylo/platform/core/shared_name_kind.h"
#include "asylo/platform/core/trusted_global_state.h"
#include "asylo/platform/posix/io/io_manager.h"
#include "asylo/platform/posix/io/native_paths.h"
#include "asylo/platform/posix/io/random_devices.h"
#include "asylo/platform/posix/threading/thread_manager.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/platform/primitives/util/status_serializer.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

using ::asylo::primitives::EntryHandler;
using ::asylo::primitives::Extent;
using ::asylo::primitives::MessageReader;
using ::asylo::primitives::MessageWriter;
using ::asylo::primitives::PrimitiveStatus;
using ::asylo::primitives::TrustedPrimitives;
using google::protobuf::RepeatedPtrField;

namespace asylo {
namespace {

void LogError(const Status &status) {
  EnclaveState state = GetState();
  if (state < EnclaveState::kUserInitializing) {
    // LOG() is unavailable here because the I/O subsystem has not yet been
    // initialized.
    TrustedPrimitives::DebugPuts(status.ToString().c_str());
  } else {
    LOG(ERROR) << status;
  }
}

// Validates that the address-range [|address|, |address| + |size|) is fully
// contained in enclave trusted memory.
PrimitiveStatus VerifyTrustedAddressRange(void *address, size_t size) {
  if (!TrustedPrimitives::IsInsideEnclave(address, size)) {
    return PrimitiveStatus(
        primitives::AbslStatusCode::kInvalidArgument,
        "Unexpected reference to resource outside the enclave trusted memory.");
  }
  return PrimitiveStatus::OkStatus();
}

// Handler installed by the runtime to initialize the enclave.
PrimitiveStatus Initialize(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);
  auto input_extent = in->next();
  auto name_extent = in->next();

  ASYLO_RETURN_IF_ERROR(
      VerifyTrustedAddressRange(input_extent.data(), input_extent.size()));

  ASYLO_RETURN_IF_ERROR(
      VerifyTrustedAddressRange(name_extent.data(), name_extent.size()));

  char *output = nullptr;
  size_t output_len = 0;
  int result = 0;
  try {
    result = asylo::__asylo_user_init(/*name=*/name_extent.As<char>(),
                                      /*config=*/input_extent.As<char>(),
                                      /*config_len=*/input_extent.size(),
                                      &output, &output_len);
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  if (!result) {
    out->PushByCopy(Extent{output, output_len});
  }
  free(output);
  return PrimitiveStatus(result);
}

// Handler installed by the runtime to invoke the enclave run entry point.
PrimitiveStatus Run(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  auto input_extent = in->next();
  char *output = nullptr;
  size_t output_len = 0;
  int result = 0;
  try {
    result = asylo::__asylo_user_run(input_extent.As<char>(),
                                     input_extent.size(), &output, &output_len);
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  if (!result) {
    out->PushByCopy(Extent{output, output_len});
  }
  free(output);
  return PrimitiveStatus(result);
}

// Handler installed by the runtime to invoke the enclave finalization entry
// point.
PrimitiveStatus Finalize(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  auto input_extent = in->next();
  char *output = nullptr;
  size_t output_len = 0;
  int result = 0;
  try {
    result = asylo::__asylo_user_fini(
        input_extent.As<char>(), input_extent.size(), &output, &output_len);
  } catch (...) {
    TrustedPrimitives::BestEffortAbort("Uncaught exception in enclave");
  }
  if (!result) {
    out->PushByCopy(Extent{output, output_len});
  }
  free(output);
  return PrimitiveStatus(result);
}

}  // namespace

Status VerifyOutputArguments(char **output, size_t *output_len) {
  if (!output || !output_len) {
    Status status = absl::InvalidArgumentError(
        "Invalid input parameter passed to __asylo_user...()");
    LogError(status);
    return status;
  }
  return absl::OkStatus();
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
      return absl::InvalidArgumentError(
          "Environment variables should set both name and value "
          "fields");
    }
    int overwrite = 0;
    setenv(variable.name().c_str(), variable.value().c_str(), overwrite);
  }
  return absl::OkStatus();
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
// See asylo/platform/core/entry_points.h for detailed documentation for each
// function.
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
    status = absl::InvalidArgumentError("Failed to parse EnclaveConfig");
    return status_serializer.Serialize(status);
  }

  status = VerifyAndSetState(EnclaveState::kUninitialized,
                             EnclaveState::kInternalInitializing);
  if (!status.ok()) {
    return status_serializer.Serialize(status);
  }

  SetEnclaveName(name);
  // Invoke the enclave entry-point.
  status = GetApplicationInstance()->InitializeInternal(enclave_config);
  if (!status.ok()) {
    SetState(EnclaveState::kUninitialized);
    return status_serializer.Serialize(status);
  }

  SetState(EnclaveState::kRunning);
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
    status = absl::InvalidArgumentError("Failed to parse EnclaveInput");
    return status_serializer.Serialize(status);
  }

  if (GetState() != EnclaveState::kRunning) {
    status = absl::FailedPreconditionError("Enclave not in state RUNNING");
    return status_serializer.Serialize(status);
  }

  // Invoke the enclave entry-point.
  status = GetApplicationInstance()->Run(enclave_input, &enclave_output);
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
    status = absl::InvalidArgumentError("Failed to parse EnclaveFinal");
    return status_serializer.Serialize(status);
  }

  status = VerifyAndSetState(EnclaveState::kRunning, EnclaveState::kFinalizing);
  if (!status.ok()) {
    return status_serializer.Serialize(status);
  }

  // Invoke the enclave entry-point.
  status = GetApplicationInstance()->Finalize(enclave_final);

  ThreadManager *thread_manager = ThreadManager::GetInstance();
  thread_manager->Finalize();

  SetState(EnclaveState::kFinalized);
  return status_serializer.Serialize(status);
}

}  // extern "C"

}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  // Register the enclave initialization entry handler.
  EntryHandler init_handler{asylo::Initialize};
  if (!TrustedPrimitives::RegisterEntryHandler(asylo::kSelectorAsyloInit,
                                               init_handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }
  // Register the enclave run entry handler.
  EntryHandler run_handler{asylo::Run};
  if (!TrustedPrimitives::RegisterEntryHandler(asylo::kSelectorAsyloRun,
                                               run_handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }

  // Register the enclave finalization entry handler.
  EntryHandler finalize_handler{asylo::Finalize};
  if (!TrustedPrimitives::RegisterEntryHandler(asylo::kSelectorAsyloFini,
                                               finalize_handler)
           .ok()) {
    TrustedPrimitives::BestEffortAbort("Could not register entry handler");
  }

  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
