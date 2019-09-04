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

#include "asylo/platform/arch/sgx/untrusted/sgx_client.h"

#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"

namespace asylo {


EnclaveLoadConfig SgxLoader::GetEnclaveLoadConfig() const {
  EnclaveLoadConfig load_config;
  SgxLoadConfig sgx_config;
  SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(enclave_path_);
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(debug_);
  *load_config.MutableExtension(sgx_load_config) = sgx_config;
  return load_config;
}

EnclaveLoadConfig SgxEmbeddedLoader::GetEnclaveLoadConfig() const {
  EnclaveLoadConfig load_config;
  SgxLoadConfig sgx_config;
  SgxLoadConfig::EmbeddedEnclaveConfig embedded_enclave_config;
  embedded_enclave_config.set_section_name(section_name_);
  *sgx_config.mutable_embedded_enclave_config() = embedded_enclave_config;
  sgx_config.set_debug(debug_);
  *load_config.MutableExtension(sgx_load_config) = sgx_config;
  return load_config;
}
}  //  namespace asylo
