/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/identity/sgx/sgx_infrastructural_enclave_manager.h"

#include <utility>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/pce_util.h"
#include "asylo/identity/sgx/platform_provisioning.h"

namespace asylo {

SgxInfrastructuralEnclaveManager::SgxInfrastructuralEnclaveManager(
    std::unique_ptr<sgx::IntelArchitecturalEnclaveInterface> intel_ae_interface,
    const EnclaveClient *assertion_generator_enclave)
    : intel_ae_interface_(std::move(intel_ae_interface)),
      assertion_generator_enclave_(assertion_generator_enclave) {}

Status SgxInfrastructuralEnclaveManager::AgeGenerateKeyAndCsr(
    const sgx::TargetInfoProto &pce_target_info,
    const std::vector<std::string> &target_certificate_authorities,
    sgx::ReportProto *report, std::string *pce_sign_report_payload,
    std::vector<asylo::CertificateSigningRequest> *csrs) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

StatusOr<sgx::ReportProto>
SgxInfrastructuralEnclaveManager::AgeGeneratePceInfoHardwareReport(
    const sgx::TargetInfoProto &pce_target_info,
    const asylo::AsymmetricEncryptionKeyProto &ppid_encryption_key) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

StatusOr<SealedSecret> SgxInfrastructuralEnclaveManager::AgeUpdateCerts(
    const std::vector<asylo::CertificateChain> &cert_chains) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

Status SgxInfrastructuralEnclaveManager::AgeStartServer() {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

Status SgxInfrastructuralEnclaveManager::AgeStartServer(
    const asylo::SealedSecret &secret) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

Status SgxInfrastructuralEnclaveManager::PceGetTargetInfo(
    sgx::TargetInfoProto *pce_target_info, sgx::PceSvn *pce_svn) {
  sgx::Targetinfo pce_target_info_out;
  uint16_t pce_svn_out;
  ASYLO_RETURN_IF_ERROR(intel_ae_interface_->GetPceTargetinfo(
      &pce_target_info_out, &pce_svn_out));

  pce_target_info->set_value(
      ConvertTrivialObjectToBinaryString(pce_target_info_out));
  pce_svn->set_value(pce_svn_out);

  return Status::OkStatus();
}

Status SgxInfrastructuralEnclaveManager::PceGetInfo(
    const sgx::ReportProto &report_proto,
    const asylo::AsymmetricEncryptionKeyProto &ppidek, sgx::PceSvn *pce_svn,
    sgx::PceId *pce_id, asylo::SignatureScheme *pck_signature_scheme,
    std::string *encrypted_ppid) {
  sgx::Report report;
  ASYLO_ASSIGN_OR_RETURN(report,
                         ConvertReportProtoToHardwareReport(report_proto));

  std::vector<uint8_t> serialized_ppidek;
  ASYLO_ASSIGN_OR_RETURN(serialized_ppidek, sgx::SerializePpidek(ppidek));

  // This conversion is guaranteed to produce a value because |ppidek| was
  // successfully serialized.
  uint8_t crypto_suite = sgx::AsymmetricEncryptionSchemeToPceCryptoSuite(
                             ppidek.encryption_scheme())
                             .value();

  uint16_t pce_svn_out;
  uint16_t pce_id_out;
  uint8_t signature_scheme_out;

  ASYLO_RETURN_IF_ERROR(intel_ae_interface_->GetPceInfo(
      report, serialized_ppidek, crypto_suite, encrypted_ppid, &pce_svn_out,
      &pce_id_out, &signature_scheme_out));

  pce_svn->set_value(pce_svn_out);
  pce_id->set_value(pce_id_out);
  *pck_signature_scheme =
      sgx::PceSignatureSchemeToSignatureScheme(signature_scheme_out);

  return Status::OkStatus();
}

StatusOr<Signature> SgxInfrastructuralEnclaveManager::PceSignReport(
    const sgx::PceSvn &pck_target_pce_svn,
    const sgx::CpuSvn &pck_target_cpu_svn,
    const sgx::ReportProto &report_proto) {
  sgx::Report report;
  ASYLO_ASSIGN_OR_RETURN(report,
                         ConvertReportProtoToHardwareReport(report_proto));

  ASYLO_RETURN_IF_ERROR(ValidatePceSvn(pck_target_pce_svn));
  ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(pck_target_cpu_svn));

  std::string signature;
  ASYLO_RETURN_IF_ERROR(intel_ae_interface_->PceSignReport(
      report, pck_target_pce_svn.value(), pck_target_cpu_svn.value(),
      &signature));

  // As of Intel SGX SDK v2.6, the PCE uses ECDSA-P256-SHA256
  return sgx::CreateSignatureFromPckEcdsaP256Sha256Signature(signature);
}

}  // namespace asylo
