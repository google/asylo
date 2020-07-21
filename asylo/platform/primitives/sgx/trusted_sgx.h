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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_

// This file declares the trusted runtime interface for SGX.

#include <sys/types.h>

#include <cstdint>

#include "asylo/platform/system_call/type_conversions/types.h"
#include "include/sgx_report.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"

namespace asylo {
namespace primitives {

// Invokes the registered handler with pointers to input and output message for
// the trusted entry point designated by |selector|. Returns a non-zero error
// code on failure. This function is the one and only entry point inside the
// enclave for any enclave call, including initialization and trusted function
// calls.
int asylo_enclave_call(uint64_t selector, void *buffer);

// Exits the enclave and triggers the fork routine.
pid_t InvokeFork(const char *enclave_name, bool restore_snapshot);

// Sends the signal to registered signal handler through SignalManager.
int DeliverSignal(int klinux_signum, int klinux_sigcode);

int RegisterSignalHandler(int signum,
                          void (*klinux_sigaction)(int, klinux_siginfo_t *,
                                                   void *),
                          const sigset_t mask, int flags);

// Allocates |count| buffers of size |size| on the untrusted heap, returning a
// pointer to an array of buffer pointers.
void **AllocateUntrustedBuffers(size_t count, size_t size);

// Releases memory on the untrusted heap pointed to by buffer pointers stored in
// |free_list|.
void DeAllocateUntrustedBuffers(void **free_list, size_t count);

// Exits the enclave and calls into the Intel Data Center Attestation Primitives
// library to set the platform quote config.
uint32_t enc_untrusted_ql_set_quote_config(const sgx_ql_config_t *config);

// Exits the enclave and calls into the Intel Data Center Attestation Primitives
// library to get the target info required to build a report targeting the Intel
// Quoting enclave. This function is expected to be called before generating the
// `sgx_report_t` to be passed to `enc_untrusted_qe_get_quote`, as SGX requires
// reports to be targeted to specific enclaves.
uint32_t enc_untrusted_qe_get_target_info(sgx_target_info_t *qe_target_info);

// Exits the enclave and calls into the Intel Data Center Attestation Primitives
// library to get the size of the buffer required to hold a quote. This function
// is expected to be called to get the appropriate quote buffer size before
// calling `enc_untrusted_qe_get_quote`.
uint32_t enc_untrusted_qe_get_quote_size(uint32_t *quote_size);

// Exits the enclave and calls into the Intel Data Center Attestation Primitives
// library to get a remotely verifiable |quote| of an enclave's identity. The
// enclave to be attested must first generate |app_report|, a locally-verifiable
// attestation, then pass it to this function. The Intel quoting enclave will
// verify |app_report| and generate a remotely verifiable attestation which is
// stored in |quote|. |quote_size| must be large enough to hold the full
// |quote|, or the function will fail with an error.
uint32_t enc_untrusted_qe_get_quote(const sgx_report_t *app_report,
                                    uint32_t quote_size, uint8_t *quote);

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_TRUSTED_SGX_H_
