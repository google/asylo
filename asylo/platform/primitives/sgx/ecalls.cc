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

// Stubs invoked by edger8r-generated code for calls into the enclave.


#include <cerrno>
#include <cstring>
#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/sgx/fork.h"
#include "asylo/platform/primitives/sgx/generated_bridge_t.h"
#include "asylo/platform/primitives/sgx/trusted_sgx.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/util/status.h"
#include "include/sgx_trts.h"

// Edger8r does basic sanity checks for input and output pointers. The
// parameters passed by the untrusted caller are copied by the edger8r-generated
// code into trusted memory and then passed here. Consequently, there is no
// possibility for TOCTOU attacks on these parameters.

// Invokes the enclave snapshotting entry-point. Returns a non-zero error code
// on failure.
int ecall_take_snapshot(char **output, uint64_t *output_len) {
  int result = 0;
  size_t tmp_output_len;
  try {
    result = asylo::TakeSnapshot(output, &tmp_output_len);
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  if (output_len) {
    *output_len = static_cast<uint64_t>(tmp_output_len);
  }
  return result;
}

// Invokes the enclave restoring entry-point. Returns a non-zero error code on
// failure.
int ecall_restore(const char *input, uint64_t input_len, char **output,
                  uint64_t *output_len) {
  if (!asylo::primitives::TrustedPrimitives::IsOutsideEnclave(input,
                                                              input_len) ||
      !asylo::primitives::TrustedPrimitives::IsOutsideEnclave(
          output_len, sizeof(uint64_t)) ||
      !asylo::primitives::TrustedPrimitives::IsOutsideEnclave(output,
                                                              sizeof(char *))) {
    asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "ecall_restore: input/output found to not be in untrusted memory.");
  }
  int result = 0;
  size_t tmp_output_len;
  try {
    result = asylo::Restore(input, static_cast<size_t>(input_len), output,
                            &tmp_output_len);
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  if (output_len) {
    *output_len = static_cast<uint64_t>(tmp_output_len);
  }
  return result;
}

// Invokes the enclave secure snapshot key transfer entry-point. Returns a
// non-zero error code on failure.
int ecall_transfer_secure_snapshot_key(const char *input, uint64_t input_len,
                                       char **output, uint64_t *output_len) {
  int result = 0;
  uint64_t bridge_output_len;
  try {
    result = asylo::TransferSecureSnapshotKey(
        input, static_cast<size_t>(input_len), output, &bridge_output_len);
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }
  if (output_len) {
    *output_len = static_cast<size_t>(bridge_output_len);
  }
  return result;
}

// Invokes the trusted entry point designated by |selector|. Returns a
// non-zero error code on failure.
int ecall_dispatch_trusted_call(uint64_t selector, void *buffer) {
  return asylo::primitives::asylo_enclave_call(selector, buffer);
}

// Invokes the enclave signal handling entry-point. Returns a non-zero error
// code on failure.
int ecall_deliver_signal(int signum, int sigcode) {
  int result = 0;
  try {
    result = asylo::primitives::DeliverSignal(signum, sigcode);
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }
  return result;
}
