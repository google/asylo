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

#ifndef ASYLO_BAZEL_APPLICATION_WRAPPER_APPLICATION_WRAPPER_DRIVER_MAIN_H_
#define ASYLO_BAZEL_APPLICATION_WRAPPER_APPLICATION_WRAPPER_DRIVER_MAIN_H_

#include <string>

#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/util/statusor.h"

// A function that returns an EnclaveConfig to be used by the application
// enclave. This function will only ever be called once.
extern "C" asylo::EnclaveConfig GetApplicationConfig();

namespace asylo {

// The core logic of the whole-application wrapper driver. Loads the application
// enclave from |loader|, runs the enclave with the given command-line
// arguments, and destroys the enclave after main() returns. Returns the
// main_return_value from the enclave's output.
//
// Assumes that EnclaveManager has already been configured.
StatusOr<int> ApplicationWrapperDriverMain(const EnclaveLoader &loader,
                                           const std::string &enclave_name,
                                           int argc, char *argv[]);

}  // namespace asylo

#endif  // ASYLO_BAZEL_APPLICATION_WRAPPER_APPLICATION_WRAPPER_DRIVER_MAIN_H_
