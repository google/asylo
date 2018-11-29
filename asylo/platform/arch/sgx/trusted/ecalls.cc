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
#include "asylo/platform/arch/include/trusted/entry_points.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/arch/sgx/trusted/generated_bridge_t.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"
#include "include/sgx_trts.h"

// Edger8r does basic sanity checks for input and output pointers. The
// parameters passed by the untrusted caller are copied by the edger8r-generated
// code into trusted memory and then passed here. Consequently, there is no
// possibility for TOCTOU attacks on these parameters.

// Invokes the enclave initialization entry-point. Returns a non-zero error code
// on failure.
int ecall_initialize(const char *name, const char *input,
                     bridge_size_t input_len, char **output,
                     bridge_size_t *output_len) {
  int result = 0;
  try {
    result =
        asylo::__asylo_user_init(name, input, static_cast<size_t>(input_len),
                                 output, static_cast<size_t *>(output_len));
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  return result;
}

// Invokes the enclave run entry-point. Returns a non-zero error code on
// failure.
int ecall_run(const char *input, bridge_size_t input_len, char **output,
              bridge_size_t *output_len) {
  int result = 0;
  try {
    result = asylo::__asylo_user_run(input, static_cast<size_t>(input_len),
                                     output, static_cast<size_t *>(output_len));
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  return result;
}

int ecall_donate_thread() { return asylo::__asylo_threading_donate(); }

// Invokes the enclave signal handling entry-point. Returns a non-zero error
// code on failure.
int ecall_handle_signal(const char *input, bridge_size_t input_len) {
  int result = 0;
  try {
    result =
        asylo::__asylo_handle_signal(input, static_cast<size_t>(input_len));
  } catch (...) {
    // Abort directly here instead of LOG(FATAL). LOG tries to obtain a mutex,
    // and acquiring a non-reentrant mutex in signal handling may cause deadlock
    // if the thread had already obtained that mutex when interrupted.
    abort();
  }
  return result;
}

// Invokes the enclave finalization entry-point. Returns a non-zero error code
// on failure.
int ecall_finalize(const char *input, bridge_size_t input_len, char **output,
                   bridge_size_t *output_len) {
  int result = 0;
  try {
    result =
        asylo::__asylo_user_fini(input, static_cast<size_t>(input_len), output,
                                 static_cast<size_t *>(output_len));
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  return result;
}

// Invokes the enclave snapshotting entry-point. Returns a non-zero error code
// on failure.
int ecall_take_snapshot(char **output, bridge_size_t *output_len) {
  int result = 0;
  try {
    result =
        asylo::__asylo_take_snapshot(output, static_cast<size_t *>(output_len));
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }
  return result;
}

// Invokes the enclave restoring entry-point. Returns a non-zero error code on
// failure.
int ecall_restore(const char *input, bridge_size_t input_len, char **output,
                  bridge_size_t *output_len) {
  int result = 0;
  try {
    result = asylo::__asylo_restore(input, static_cast<size_t>(input_len),
                                    output, static_cast<size_t *>(output_len));
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }
  return result;
}
