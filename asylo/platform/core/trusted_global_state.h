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

#ifndef ASYLO_PLATFORM_CORE_TRUSTED_GLOBAL_STATE_H_
#define ASYLO_PLATFORM_CORE_TRUSTED_GLOBAL_STATE_H_

// Defines an interface to runtime state global to an enclave application.

#include <string>

#include "asylo/enclave.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Sets the name of this enclave, as specified to the enclave manager at the
// time this enclave was loaded.
void SetEnclaveName(const std::string &name);

// Gets the name of this enclave, as specified to the enclave manager at the
// time this enclave was loaded.
const std::string &GetEnclaveName();

// Sets the enclave config, as specified to the enclave manager at the time this
// enclave was loaded.
Status SetEnclaveConfig(const EnclaveConfig &config);

// Returns the enclave config, as specified to the enclave manager at the time
// this enclave was loaded. Returns an error if no enclave config is seti (i.e.,
// if it is called before SetEnclaveConfig has ever been called).
StatusOr<const EnclaveConfig *> GetEnclaveConfig();

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_TRUSTED_GLOBAL_STATE_H_
