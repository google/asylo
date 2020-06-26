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

#include "asylo/identity/attestation/sgx/internal/report_oracle_enclave_wrapper.h"
#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/random/distributions.h"
#include "absl/random/random.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/attestation/sgx/internal/report_oracle_enclave.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

std::string RandomName() {
  absl::BitGen bitgen;
  auto rand64 = [&bitgen] {
    return absl::Hex(absl::Uniform<uint64_t>(bitgen), absl::kZeroPad16);
  };
  return absl::StrCat("Report Oracle ", rand64(), rand64());
}

}  // namespace

StatusOr<std::unique_ptr<ReportOracleEnclaveWrapper>>
ReportOracleEnclaveWrapper::LoadFromFile(absl::string_view enclave_path) {
  std::string enclave_name = RandomName();

  EnclaveManager *enclave_manager;
  ASYLO_ASSIGN_OR_RETURN(enclave_manager, EnclaveManager::Instance());

  EnclaveLoadConfig load_config;
  load_config.set_name(enclave_name);

  SgxLoadConfig sgx_config;
  SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(std::string(enclave_path));
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  *load_config.MutableExtension(sgx_load_config) = sgx_config;

  ASYLO_RETURN_IF_ERROR(enclave_manager->LoadEnclave(load_config));

  return absl::WrapUnique<ReportOracleEnclaveWrapper>(
      new ReportOracleEnclaveWrapper(enclave_manager,
                                     enclave_manager->GetClient(enclave_name)));
}

StatusOr<std::unique_ptr<ReportOracleEnclaveWrapper>>
ReportOracleEnclaveWrapper::LoadFromSection(absl::string_view section_name) {
  std::string enclave_name = RandomName();

  EnclaveManager *enclave_manager;
  ASYLO_ASSIGN_OR_RETURN(enclave_manager, EnclaveManager::Instance());

  EnclaveLoadConfig load_config;
  load_config.set_name(enclave_name);

  SgxLoadConfig sgx_config;
  SgxLoadConfig::EmbeddedEnclaveConfig embedded_enclave_config;
  embedded_enclave_config.set_section_name(std::string(section_name));
  *sgx_config.mutable_embedded_enclave_config() = embedded_enclave_config;
  sgx_config.set_debug(true);

  *load_config.MutableExtension(sgx_load_config) = sgx_config;

  ASYLO_RETURN_IF_ERROR(enclave_manager->LoadEnclave(load_config));

  return absl::WrapUnique<ReportOracleEnclaveWrapper>(
      new ReportOracleEnclaveWrapper(enclave_manager,
                                     enclave_manager->GetClient(enclave_name)));
}

ReportOracleEnclaveWrapper::~ReportOracleEnclaveWrapper() {
  ASYLO_CHECK_OK(enclave_manager_->DestroyEnclave(
      enclave_client_, EnclaveFinal{}, /*skip_finalize=*/false));
}

StatusOr<Report> ReportOracleEnclaveWrapper::GetReport(
    const Targetinfo &targetinfo, const Reportdata &reportdata) {
  EnclaveInput enclave_input;
  ReportOracleEnclaveInput_GetReport *get_report_input =
      enclave_input.MutableExtension(report_oracle_enclave_input)
          ->mutable_get_report();
  get_report_input->mutable_target_info()->set_value(
      ConvertTrivialObjectToBinaryString(targetinfo));
  get_report_input->set_reportdata(
      ConvertTrivialObjectToBinaryString(reportdata));

  EnclaveOutput enclave_output;
  ASYLO_RETURN_IF_ERROR(
      enclave_client_->EnterAndRun(enclave_input, &enclave_output));

  return ConvertReportProtoToHardwareReport(
      enclave_output.GetExtension(report_oracle_enclave_output)
          .get_report()
          .report());
}

}  // namespace sgx
}  // namespace asylo
