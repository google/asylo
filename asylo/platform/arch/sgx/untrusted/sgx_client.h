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

#ifndef ASYLO_PLATFORM_ARCH_SGX_UNTRUSTED_SGX_CLIENT_H_
#define ASYLO_PLATFORM_ARCH_SGX_UNTRUSTED_SGX_CLIENT_H_

#include <string>

#include "absl/base/macros.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/core/enclave_manager.h"

namespace asylo {

/// Enclave loader for Intel Software Guard Extensions (SGX) based enclaves
/// located in shared object files read from the file system.
/// \deprecated Use EnclaveLoadConfig directly instead of this loader, or use
///             LoadEnclave from EnclaveManager.
class SgxLoader : public EnclaveLoader {
 public:
  /// Constructs an SgxLoader for an enclave object file on the file system,
  /// optionally in debug mode.
  ///
  /// \param path The path to the enclave binary (.so) file to load.
  /// \param debug Whether to load the enclave in debug mode.
  SgxLoader(absl::string_view path, bool debug)
      : enclave_path_(path), debug_(debug) {}

 private:
  EnclaveLoadConfig GetEnclaveLoadConfig() const override;

  const std::string enclave_path_;
  const bool debug_;
};

/// Enclave loader for Intel Software Guard Extensions (SGX) based enclaves
/// embedded in the binary of the calling process.
/// \deprecated Use EnclaveLoadConfig directly instead of this loader, or use
///             LoadEnclave from EnclaveManager.
class SgxEmbeddedLoader : public EnclaveLoader {
 public:
  /// Constructs an SgxEmbeddedLoader for an enclave object embedded in the
  /// binary of the calling process.
  ///
  /// \param elf_section_name The name of the ELF section containing the
  ///                         enclave.
  /// \param debug Whether to load the enclave in debug mode.
  SgxEmbeddedLoader(absl::string_view elf_section_name, bool debug)
      : section_name_(elf_section_name), debug_(debug) {}

 private:
  EnclaveLoadConfig GetEnclaveLoadConfig() const override;

  const std::string section_name_;
  const bool debug_;
};

}  //  namespace asylo
#endif  // ASYLO_PLATFORM_ARCH_SGX_UNTRUSTED_SGX_CLIENT_H_
