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

#include "asylo/platform/primitives/sgx/trusted_sgx.h"

#include <errno.h>
#include <signal.h>
#include <sys/types.h>

#include <vector>

#include "absl/strings/str_cat.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/posix/signal/signal_manager.h"
#include "asylo/platform/posix/threading/thread_manager.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/sgx/generated_bridge_t.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/sgx/sgx_params.h"
#include "asylo/platform/primitives/sgx/untrusted_cache_malloc.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/trusted_memory.h"
#include "asylo/platform/primitives/util/trusted_runtime_helper.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "include/sgx_trts.h"

#define CHECK_OCALL(status)                                                  \
  do {                                                                       \
    sgx_status_t sgx_status = status;                                        \
    if (sgx_status != SGX_SUCCESS) {                                         \
      TrustedPrimitives::BestEffortAbort(                                    \
          absl::StrCat(__FILE__, ":", __LINE__, ": ",                        \
                       asylo::Status(sgx_status, "ocall failed").ToString()) \
              .c_str());                                                     \
    }                                                                        \
  } while (0)

namespace asylo {
namespace primitives {

int RegisterSignalHandler(int signum,
                          void (*klinux_sigaction)(int, klinux_siginfo_t *,
                                                   void *),
                          const sigset_t mask, int flags) {
  int klinux_signum = TokLinuxSignalNumber(signum);
  if (klinux_signum < 0) {
    errno = EINVAL;
    return -1;
  }
  klinux_sigset_t klinux_mask;
  TokLinuxSigset(&mask, &klinux_mask);
  int ret;
  CHECK_OCALL(ocall_enc_untrusted_register_signal_handler(
      &ret, klinux_signum, reinterpret_cast<void *>(klinux_sigaction),
      reinterpret_cast<void *>(&klinux_mask), sizeof(klinux_mask),
      TokLinuxSignalFlag(flags)));
  return ret;
}

int DeliverSignal(int linux_signum, int linux_sigcode) {
  int signum = FromkLinuxSignalNumber(linux_signum);
  if (signum < 0) {
    return 1;
  }
  siginfo_t info;
  info.si_signo = signum;
  info.si_code = linux_sigcode;
  SignalManager *signal_manager = SignalManager::GetInstance();
  const sigset_t mask = signal_manager->GetSignalMask();

  // If the signal is blocked and still passed into the enclave. The signal
  // masks inside the enclave is out of sync with the untrusted signal mask.
  if (sigismember(&mask, signum)) {
    return -1;
  }
  signal_manager->HandleSignal(signum, &info, /*ucontext=*/nullptr);
  return 0;
}

pid_t InvokeFork(const char *enclave_name, bool restore_snapshot) {
  int32_t ret;
  sgx_status_t status =
      ocall_enc_untrusted_fork(&ret, enclave_name, restore_snapshot);
  if (status != SGX_SUCCESS) {
    errno = EINTR;
    return -1;
  }
  return ret;
}

// Entry handler installed by the runtime to finalize the enclave at the time it
// is destroyed.
PrimitiveStatus FinalizeEnclave(void *context, MessageReader *in,
                                MessageWriter *out) {
  if (in) {
    ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);
  }
  // Delete instance of the global memory pool singleton freeing all memory held
  // by the pool.
  delete UntrustedCacheMalloc::Instance();
  return asylo_enclave_fini();
}

// Entry handler installed by the runtime to start the created thread.
PrimitiveStatus DonateThread(void *context, MessageReader *in,
                             MessageWriter *out) {
  if (in) {
    ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(*in, 1);
  }
  int result = 0;
  try {
    ThreadManager *thread_manager = ThreadManager::GetInstance();
    result = thread_manager->StartThread(in->next<pid_t>());
  } catch (...) {
    TrustedPrimitives::BestEffortAbort(
        "Uncaught exception in enclave entry handler: DonateThread. Failed to "
        "get ThreadManager instance or start the thread.");
  }
  return PrimitiveStatus(result);
}

// Registers internal handlers, including entry handlers.
void RegisterInternalHandlers() {
  // Register the enclave donate thread entry handler.
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloDonateThread,
                                               EntryHandler{DonateThread})
           .ok()) {
    TrustedPrimitives::BestEffortAbort(
        "Could not register entry handler: DonateThread.");
  }

  // Register the enclave finalization entry handler.
  if (!TrustedPrimitives::RegisterEntryHandler(kSelectorAsyloFini,
                                               EntryHandler{FinalizeEnclave})
           .ok()) {
    TrustedPrimitives::BestEffortAbort(
        "Could not register entry handler: FinalizeEnclave");
  }
}

void TrustedPrimitives::BestEffortAbort(const char *message) {
  DebugPuts(message);
  delete UntrustedCacheMalloc::Instance();
  enc_reject_entries();
  MarkEnclaveAborted();
  abort();
}

PrimitiveStatus TrustedPrimitives::RegisterEntryHandler(
    uint64_t selector, const EntryHandler &handler) {
  return asylo::primitives::RegisterEntryHandler(selector, handler);
}

int asylo_enclave_call(uint64_t selector, void *buffer) {
  SgxParams *const sgx_params = reinterpret_cast<SgxParams *>(buffer);
  if (!IsValidUntrustedAddress(sgx_params)) {
    PrimitiveStatus status{primitives::AbslStatusCode::kInvalidArgument,
                           "input should lie within untrusted memory."};
    return status.error_code();
  }

  const void *input = sgx_params->input;
  size_t input_size = sgx_params->input_size;
  size_t output_size = 0;

  MessageReader in;
  MessageWriter out;
  // Copy untrusted input to a trusted buffer before deserializing to prevent
  // TOC/TOU attacks.
  auto trusted_input = CopyFromUntrusted(input, input_size);
  if (trusted_input) {
    in.Deserialize(trusted_input.get(), input_size);
  }

  PrimitiveStatus status = InvokeEntryHandler(selector, &in, &out);

  // Serialize |out| to untrusted memory and pass that as output. The untrusted
  // caller is still responsible for freeing |*output|, which now points to
  // untrusted memory.
  output_size = out.MessageSize();
  if (out.MessageSize() > 0) {
    // Serialize to a trusted output buffer first to prevent TOC/TOU attacks.
    std::unique_ptr<char[]> trusted_output(new char[output_size]);
    out.Serialize(trusted_output.get());
    sgx_params->output = CopyToUntrusted(trusted_output.get(), output_size);
  }
  sgx_params->output_size = static_cast<uint64_t>(output_size);
  return status.error_code();
}

// For SGX, UntrustedLocalAlloc uses malloc() on the untrusted host to
// allocate memory.
void *TrustedPrimitives::UntrustedLocalAlloc(size_t size) noexcept {
  void *result;
  CHECK_OCALL(
      ocall_untrusted_local_alloc(&result, static_cast<uint64_t>(size)));
  if (result && !IsOutsideEnclave(result, static_cast<uint64_t>(size))) {
    TrustedPrimitives::BestEffortAbort(
        "Allocated memory not found to be outside the enclave.");
  }

  // On error, malloc returns nullptr and sets errno to ENOMEM.
  if (!result) {
    errno = ENOMEM;
    TrustedPrimitives::DebugPuts("UntrustedLocalAlloc on SGX failed.");
  }
  return result;
}

// For SGX, UntrustedLocalFree uses free() on the untrusted host to free the
// memory allocated by UntrustedLocalAlloc.
void TrustedPrimitives::UntrustedLocalFree(void *ptr) noexcept {
  CHECK_OCALL(ocall_untrusted_local_free(ptr));
}

// Since untrusted memory is directly accessible in SGX, we perform no pointer
// validation before copying the memory.
void *TrustedPrimitives::UntrustedLocalMemcpy(void *dest, const void *src,
                                              size_t size) noexcept {
  return memcpy(dest, src, size);
}

bool TrustedPrimitives::IsInsideEnclave(const void *addr, size_t size) {
  return sgx_is_within_enclave(addr, size) == 1;
}

bool TrustedPrimitives::IsOutsideEnclave(const void *addr, size_t size) {
  return sgx_is_outside_enclave(addr, size) == 1;
}

void TrustedPrimitives::DebugPuts(const char *message) {
  int result;
  CHECK_OCALL(ocall_untrusted_debug_puts(&result, message));
  if (result < 0) {
    errno = EOF;
  }
}

PrimitiveStatus TrustedPrimitives::UntrustedCall(uint64_t untrusted_selector,
                                                 MessageWriter *input,
                                                 MessageReader *output) {
  int ret;

  UntrustedCacheMalloc *untrusted_cache = UntrustedCacheMalloc::Instance();

  SgxParams *const sgx_params =
      reinterpret_cast<SgxParams *>(untrusted_cache->Malloc(sizeof(SgxParams)));
  if (!TrustedPrimitives::IsOutsideEnclave(sgx_params, sizeof(SgxParams))) {
    TrustedPrimitives::BestEffortAbort(
        "UntrustedCall: sgx_param should be in untrusted memory");
  }
  Cleanup clean_up(
      [sgx_params, untrusted_cache] { untrusted_cache->Free(sgx_params); });
  sgx_params->input_size = 0;
  sgx_params->input = nullptr;
  if (input) {
    sgx_params->input_size = input->MessageSize();
    if (sgx_params->input_size > 0) {
      // Allocate and copy data to |input_buffer|.
      sgx_params->input = untrusted_cache->Malloc(sgx_params->input_size);
      if (!TrustedPrimitives::IsOutsideEnclave(sgx_params->input,
                                               sgx_params->input_size)) {
        TrustedPrimitives::BestEffortAbort(
            "UntrustedCall: sgx_param input should be in untrusted memory");
      }
      input->Serialize(const_cast<void *>(sgx_params->input));
    }
  }
  sgx_params->output_size = 0;
  sgx_params->output = nullptr;
  CHECK_OCALL(
      ocall_dispatch_untrusted_call(&ret, untrusted_selector, sgx_params));
  if (sgx_params->input) {
    untrusted_cache->Free(const_cast<void *>(sgx_params->input));
  }
  if (!TrustedPrimitives::IsOutsideEnclave(sgx_params->output,
                                           sgx_params->output_size)) {
    TrustedPrimitives::BestEffortAbort(
        "UntrustedCall: sgx_param output should be in untrusted memory");
  }
  if (sgx_params->output) {
    // For the results obtained in |output_buffer|, copy them to |output|
    // before freeing the buffer.
    output->Deserialize(sgx_params->output, sgx_params->output_size);
    TrustedPrimitives::UntrustedLocalFree(sgx_params->output);
  }
  return PrimitiveStatus::OkStatus();
}

// For SGX, CreateThread() needs to exit the enclave by making an UntrustedCall
// to CreateThreadHandler, which makes an EnclaveCall to enter the enclave with
// the new thread and register it with the thread manager and execute the
// intended callback.
int TrustedPrimitives::CreateThread() {
  MessageWriter input;
  MessageReader output;
  PrimitiveStatus status =
      UntrustedCall(kSelectorCreateThread, &input, &output);
  if (!status.ok()) {
    DebugPuts("CreateThread failed.");
    return -1;
  }
  if (output.size() != 1) {
    TrustedPrimitives::BestEffortAbort(
        "CreateThread error: unexpected output size received.");
  }
  return output.next<int>();
}

void **AllocateUntrustedBuffers(size_t count, size_t size) {
  void **buffers;
  CHECK_OCALL(ocall_enc_untrusted_allocate_buffers(
      &buffers, static_cast<uint64_t>(count), static_cast<uint64_t>(size)));
  if (!buffers || !TrustedPrimitives::IsOutsideEnclave(buffers, size)) {
    TrustedPrimitives::BestEffortAbort(
        "allocated buffers (for use by UntrustedCacheMalloc) found to not be "
        "in untrusted memory.");
  }
  return buffers;
}

void DeAllocateUntrustedBuffers(void **free_list, size_t count) {
  if (!IsValidUntrustedAddress(free_list)) {
    TrustedPrimitives::BestEffortAbort(
        "free_list expected to be in untrusted memory.");
  }
  CHECK_OCALL(ocall_enc_untrusted_deallocate_free_list(
      free_list, static_cast<uint64_t>(count)));
}

uint32_t enc_untrusted_ql_set_quote_config(const sgx_ql_config_t *config) {
  uint32_t result;
  CHECK_OCALL(ocall_enc_untrusted_ql_set_quote_config(
      &result, config, config->cert_data_size, config->p_cert_data));
  return result;
}

uint32_t enc_untrusted_qe_get_target_info(sgx_target_info_t *qe_target_info) {
  uint32_t result;
  CHECK_OCALL(ocall_enc_untrusted_qe_get_target_info(&result, qe_target_info));
  return result;
}

uint32_t enc_untrusted_qe_get_quote_size(uint32_t *quote_size) {
  uint32_t result;
  CHECK_OCALL(ocall_enc_untrusted_qe_get_quote_size(&result, quote_size));
  return result;
}

uint32_t enc_untrusted_qe_get_quote(const sgx_report_t *app_report,
                                    uint32_t quote_size, uint8_t *quote) {
  uint32_t result;
  CHECK_OCALL(
      ocall_enc_untrusted_qe_get_quote(&result, app_report, quote_size, quote));
  return result;
}

}  // namespace primitives
}  // namespace asylo
