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
#include "asylo/enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/identity/sgx/pce_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

Status CheckEnclaveOutputExtension(EnclaveOutput output) {
  if (!output.HasExtension(sgx::remote_assertion_generator_enclave_output)) {
    return Status(error::GoogleError::INTERNAL,
                  "Enclave output invalid: did not contain remote assertion "
                  "generator enclave output");
  }
  return Status::OkStatus();
}

}  // namespace

SgxInfrastructuralEnclaveManager::SgxInfrastructuralEnclaveManager(
    std::unique_ptr<sgx::IntelArchitecturalEnclaveInterface> intel_ae_interface,
    EnclaveClient *assertion_generator_enclave)
    : intel_ae_interface_(std::move(intel_ae_interface)),
      assertion_generator_enclave_(assertion_generator_enclave) {}

Status SgxInfrastructuralEnclaveManager::AgeGenerateKeyAndCsr(
    const sgx::TargetInfoProto &pce_target_info, sgx::ReportProto *report,
    std::string *pce_sign_report_payload,
    sgx::TargetedCertificateSigningRequest *targeted_csr) {
  EnclaveInput input;
  sgx::GenerateKeyAndCsrInput *generate_key_and_csr_request_input =
      input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
          ->mutable_generate_key_and_csr_input();
  *generate_key_and_csr_request_input->mutable_pce_target_info() =
      pce_target_info;

  EnclaveOutput output;
  ASYLO_RETURN_IF_ERROR(
      assertion_generator_enclave_->EnterAndRun(input, &output));
  ASYLO_RETURN_IF_ERROR(CheckEnclaveOutputExtension(output));
  const sgx::GenerateKeyAndCsrOutput &generate_key_and_csr_output =
      output.MutableExtension(sgx::remote_assertion_generator_enclave_output)
          ->generate_key_and_csr_output();

  *targeted_csr = generate_key_and_csr_output.targeted_csr();
  *report = generate_key_and_csr_output.report();
  *pce_sign_report_payload =
      generate_key_and_csr_output.pce_sign_report_payload();
  return Status::OkStatus();
}

StatusOr<sgx::ReportProto>
SgxInfrastructuralEnclaveManager::AgeGeneratePceInfoSgxHardwareReport(
    const sgx::TargetInfoProto &pce_target_info,
    const asylo::AsymmetricEncryptionKeyProto &ppid_encryption_key) {
  EnclaveInput input;
  sgx::GeneratePceInfoSgxHardwareReportInput
      *generate_pce_info_sgx_hardware_report_input =
          input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
              ->mutable_generate_pce_info_sgx_hardware_report_input();
  *generate_pce_info_sgx_hardware_report_input->mutable_pce_target_info() =
      pce_target_info;
  *generate_pce_info_sgx_hardware_report_input->mutable_ppid_encryption_key() =
      ppid_encryption_key;

  EnclaveOutput output;
  ASYLO_RETURN_IF_ERROR(
      assertion_generator_enclave_->EnterAndRun(input, &output));
  ASYLO_RETURN_IF_ERROR(CheckEnclaveOutputExtension(output));
  return output.GetExtension(sgx::remote_assertion_generator_enclave_output)
      .generate_pce_info_sgx_hardware_report_output()
      .report();
}

StatusOr<SealedSecret> SgxInfrastructuralEnclaveManager::AgeUpdateCerts(
    const std::vector<asylo::CertificateChain> &cert_chains) {
  EnclaveInput input;
  sgx::UpdateCertsInput *update_certs_input =
      input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
          ->mutable_update_certs_input();
  *update_certs_input->mutable_certificate_chains() = {cert_chains.begin(),
                                                       cert_chains.end()};
  update_certs_input->set_output_sealed_secret(true);

  EnclaveOutput output;
  ASYLO_RETURN_IF_ERROR(
      assertion_generator_enclave_->EnterAndRun(input, &output));
  return output
      .MutableExtension(sgx::remote_assertion_generator_enclave_output)
      ->update_certs_output()
      .sealed_secret();
}

Status SgxInfrastructuralEnclaveManager::AgeStartServer() {
  EnclaveInput input;
  *input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
       ->mutable_start_server_request_input() =
      sgx::StartServerRequestInput::default_instance();
  EnclaveOutput output;
  return assertion_generator_enclave_->EnterAndRun(input, &output);
}

Status SgxInfrastructuralEnclaveManager::AgeStartServer(
    const asylo::SealedSecret &secret) {
  EnclaveInput input;
  *input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
       ->mutable_start_server_request_input()
       ->mutable_sealed_secret() = secret;
  EnclaveOutput output;
  return assertion_generator_enclave_->EnterAndRun(input, &output);
}

StatusOr<SgxIdentity>
SgxInfrastructuralEnclaveManager::AgeGetSgxIdentity() {
  EnclaveInput input;
  *input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
       ->mutable_get_enclave_identity_input() =
      sgx::GetEnclaveIdentityInput::default_instance();

  EnclaveOutput output;
  ASYLO_RETURN_IF_ERROR(
      assertion_generator_enclave_->EnterAndRun(input, &output));
  ASYLO_RETURN_IF_ERROR(CheckEnclaveOutputExtension(output));
  const sgx::GetEnclaveIdentityOutput &get_enclave_identity_output =
      output.GetExtension(sgx::remote_assertion_generator_enclave_output)
          .get_enclave_identity_output();

  return get_enclave_identity_output.sgx_identity();
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

  uint16_t pce_svn_out;
  uint16_t pce_id_out;

  ASYLO_RETURN_IF_ERROR(intel_ae_interface_->GetPceInfo(
      report, serialized_ppidek, ppidek.encryption_scheme(), encrypted_ppid,
      &pce_svn_out, &pce_id_out, pck_signature_scheme));

  pce_svn->set_value(pce_svn_out);
  pce_id->set_value(pce_id_out);

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
