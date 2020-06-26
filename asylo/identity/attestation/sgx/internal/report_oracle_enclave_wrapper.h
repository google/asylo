/*
 *
 * Copyright 2020 Asylo authors
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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REPORT_ORACLE_ENCLAVE_WRAPPER_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REPORT_ORACLE_ENCLAVE_WRAPPER_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/platform/core/enclave_client.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Helper class that wraps all calls into the report oracle enclave. This class
// takes care of loading the enclave, marshalling parameters, etc.
class ReportOracleEnclaveWrapper {
 public:
  // Load the report oracle enclave from |enclave_path|
  static StatusOr<std::unique_ptr<ReportOracleEnclaveWrapper>> LoadFromFile(
      absl::string_view enclave_path);

  // Load the embedded report oracle enclave from ELF section |section_name|.
  static StatusOr<std::unique_ptr<ReportOracleEnclaveWrapper>> LoadFromSection(
      absl::string_view section_name);

  ~ReportOracleEnclaveWrapper();

  ReportOracleEnclaveWrapper(const ReportOracleEnclaveWrapper &) = delete;
  ReportOracleEnclaveWrapper &operator=(const ReportOracleEnclaveWrapper &) =
      delete;
  ReportOracleEnclaveWrapper(const ReportOracleEnclaveWrapper &&) = delete;
  ReportOracleEnclaveWrapper &operator=(const ReportOracleEnclaveWrapper &&) =
      delete;

  // Fetches a report from the oracle enclave over |reportdata| and targeted
  // using |targetinfo|.
  StatusOr<Report> GetReport(const Targetinfo &targetinfo,
                             const Reportdata &reportdata);

 private:
  ReportOracleEnclaveWrapper(EnclaveManager *enclave_manager,
                             EnclaveClient *enclave_client)
      : enclave_manager_(enclave_manager), enclave_client_(enclave_client) {}

  EnclaveManager *enclave_manager_;
  EnclaveClient *enclave_client_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REPORT_ORACLE_ENCLAVE_WRAPPER_H_
