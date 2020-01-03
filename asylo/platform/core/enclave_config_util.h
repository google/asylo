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

#ifndef ASYLO_PLATFORM_CORE_ENCLAVE_CONFIG_UTIL_H_
#define ASYLO_PLATFORM_CORE_ENCLAVE_CONFIG_UTIL_H_

#include "asylo/enclave.pb.h"

namespace asylo {

/// \deprecated
/// Sets critical uninitialized fields in `config` to default values.
///
/// \param host_config Values to set in the `host_config` field of
///                    `config`.
/// \param config[out] EnclaveConfig object to populate.
void SetEnclaveConfigDefaults(const HostConfig &host_config,
                              EnclaveConfig *config);

/// Sets critical uninitialized fields in `config` to default values.
///
/// \param config[out] EnclaveConfig object to populate.
void SetEnclaveConfigDefaults(EnclaveConfig *config);

/// \deprecated
/// Returns an EnclaveConfig proto with critical fields initialized to default
/// values.
///
/// \param host_config This parameter is ignored.
/// \return An EnclaveConfig proto with critical fields initialized to their
///         default values.
EnclaveConfig CreateDefaultEnclaveConfig(const HostConfig &host_config);

/// Returns an EnclaveConfig proto with critical fields initialize to default
/// values.
///
/// \return An EnclaveConfig proto with critical fields initialized to their
///         default values.
EnclaveConfig CreateDefaultEnclaveConfig();

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_ENCLAVE_CONFIG_UTIL_H_
