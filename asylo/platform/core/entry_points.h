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

#ifndef ASYLO_PLATFORM_CORE_ENTRY_POINTS_H_
#define ASYLO_PLATFORM_CORE_ENTRY_POINTS_H_

#include <unistd.h>

namespace asylo {

#ifdef __cplusplus
extern "C" {
#endif

// Asylo enclave entry points that route through TrustedApplication.
//
// In each of the following functions that return an output value, memory for
// |output| is allocated outside the enclave. If the return code from the
// function is zero (no error), then the caller can assume that |output| points
// to a buffer of size *|output_len|. In this case, the caller takes ownership
// of |output|. |output| and |output_len| are assumed to be non-null on input.
//
// In most cases, errors are propagated via |output| in the form of a serialized
// StatusProto. If a serialization failure occurs and |output| cannot be
// properly updated, then the function will return a non-zero integer code. In
// this case, the caller cannot make any assumptions about the contents of
// |output| or |output_len|.

// User-defined enclave initialization routine.
//
// The input type is asylo::EnclaveConfig.
// The output type is asylo::StatusProto.
int __asylo_user_init(const char *name, const char *config, size_t config_len,
                      char **output, size_t *output_len);

// User-defined enclave execution routine.
//
// The input type is asylo::EnclaveInput.
// The output type is asylo::EnclaveOutput.
int __asylo_user_run(const char *input, size_t input_len, char **output,
                     size_t *output_len);

// User-defined enclave finalization routine.
//
// The input type is asylo::EnclaveFinal.
// The output type is asylo::StatusProto.
int __asylo_user_fini(const char *final_input, size_t len, char **output,
                      size_t *output_len);

#ifdef __cplusplus
}  // extern "C"
#endif

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ENTRY_POINTS_H_
