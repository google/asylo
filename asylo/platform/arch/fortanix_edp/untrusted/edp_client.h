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

#ifndef ASYLO_PLATFORM_ARCH_FORTANIX_EDP_UNTRUSTED_EDP_CLIENT_H_
#define ASYLO_PLATFORM_ARCH_FORTANIX_EDP_UNTRUSTED_EDP_CLIENT_H_

#include <string>

#include "absl/base/macros.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/core/enclave_manager.h"

namespace asylo {

/// Enclave loader for Fortanix EDP based enclaves
/// located in SGXS files read from the file system.
class FortanixEdpLoader : public EnclaveLoader {
 public:
  /// Constructs an FortanixEdpLoader for an enclave object file on the file system.
  ///
  /// \param path The path to the enclave binary (.sgxs) file to load.
  FortanixEdpLoader(absl::string_view path) : enclave_path_(path) {}

 private:
  EnclaveLoadConfig GetEnclaveLoadConfig() const override;

  const std::string enclave_path_;
};

}  //  namespace asylo
#endif  // ASYLO_PLATFORM_ARCH_FORTANIX_EDP_UNTRUSTED_EDP_CLIENT_H_
