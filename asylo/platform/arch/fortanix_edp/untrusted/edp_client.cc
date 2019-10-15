/*
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
 */

#include "asylo/platform/arch/fortanix_edp/untrusted/edp_client.h"

#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/fortanix_edp/loader.pb.h"

namespace asylo {

EnclaveLoadConfig FortanixEdpLoader::GetEnclaveLoadConfig() const {
  EnclaveLoadConfig load_config;
  FortanixEdpLoadConfig edp_config;
  edp_config.set_enclave_path(enclave_path_);
  *load_config.MutableExtension(fortanix_edp_load_config) = edp_config;
  return load_config;
}

}  //  namespace asylo
