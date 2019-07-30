/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/system_call/kernel_type.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/util/status_macros.h"

using asylo::primitives::EntryHandler;
using asylo::primitives::Extent;
using asylo::primitives::MessageReader;
using asylo::primitives::MessageWriter;
using asylo::primitives::PrimitiveStatus;
using asylo::primitives::TrustedPrimitives;

namespace asylo {
namespace host_call {
namespace {

// Message handler that aborts the enclave.
PrimitiveStatus Abort(void *context, MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  TrustedPrimitives::BestEffortAbort("Aborting enclave");
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestAccess(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 2);

  const auto path_name = in->next();
  int mode = in->next<int>();

  out->Push<int>(enc_untrusted_access(path_name.As<char>(), mode));
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetpid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<pid_t>(enc_untrusted_getpid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetPpid(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<pid_t>(enc_untrusted_getppid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestSetSid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<pid_t>(enc_untrusted_setsid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetuid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<uid_t>(enc_untrusted_getuid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetgid(void *context, MessageReader *in,
                           MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<gid_t>(enc_untrusted_getgid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGeteuid(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<uid_t>(enc_untrusted_geteuid());
  return PrimitiveStatus::OkStatus();
}

PrimitiveStatus TestGetegid(void *context, MessageReader *in,
                            MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  out->Push<gid_t>(enc_untrusted_getegid());
  return PrimitiveStatus::OkStatus();
}

}  // namespace
}  // namespace host_call
}  // namespace asylo

// Implements the required enclave initialization function.
extern "C" PrimitiveStatus asylo_enclave_init() {
  init_host_calls();

  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kAbortEnclaveSelector,
      EntryHandler{asylo::host_call::Abort}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestAccess,
      EntryHandler{asylo::host_call::TestAccess}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetPid,
      EntryHandler{asylo::host_call::TestGetpid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetPpid,
      EntryHandler{asylo::host_call::TestGetPpid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestSetSid,
      EntryHandler{asylo::host_call::TestSetSid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetUid,
      EntryHandler{asylo::host_call::TestGetuid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetGid,
      EntryHandler{asylo::host_call::TestGetgid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetEuid,
      EntryHandler{asylo::host_call::TestGeteuid}));
  ASYLO_RETURN_IF_ERROR(TrustedPrimitives::RegisterEntryHandler(
      asylo::host_call::kTestGetEgid,
      EntryHandler{asylo::host_call::TestGetegid}));

  return PrimitiveStatus::OkStatus();
}

// Implements the required enclave finalization function.
extern "C" PrimitiveStatus asylo_enclave_fini() {
  return PrimitiveStatus::OkStatus();
}
