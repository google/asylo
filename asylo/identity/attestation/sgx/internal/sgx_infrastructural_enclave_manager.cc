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

#include "asylo/identity/attestation/sgx/internal/sgx_infrastructural_enclave_manager.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

Status CheckEnclaveOutputExtension(EnclaveOutput output) {
  if (!output.HasExtension(sgx::remote_assertion_generator_enclave_output)) {
    return absl::InternalError(
        "Enclave output invalid: did not contain remote assertion "
        "generator enclave output");
  }
  return absl::OkStatus();
}

}  // namespace

const char *SgxInfrastructuralEnclaveManager::kAgeClientName =
    "AssertionGeneratorEnclave";

SgxInfrastructuralEnclaveManager::SgxInfrastructuralEnclaveManager(
    std::unique_ptr<sgx::IntelArchitecturalEnclaveInterface> intel_ae_interface,
    EnclaveClient *assertion_generator_enclave)
    : intel_ae_interface_(std::move(intel_ae_interface)),
      assertion_generator_enclave_(assertion_generator_enclave) {}

EnclaveLoadConfig SgxInfrastructuralEnclaveManager::GetAgeEnclaveLoadConfig(
    std::string enclave_path, bool is_debuggable_enclave,
    std::string server_address,
    EnclaveAssertionAuthorityConfig sgx_local_assertion_authority_config,
    std::string enclave_client_name) {
  EnclaveLoadConfig load_config;
  load_config.set_name(std::move(enclave_client_name));

  SgxLoadConfig *sgx_config = load_config.MutableExtension(sgx_load_config);
  sgx_config->mutable_file_enclave_config()->set_enclave_path(
      std::move(enclave_path));
  sgx_config->set_debug(is_debuggable_enclave);

  *load_config.mutable_config()->add_enclave_assertion_authority_configs() =
      std::move(sgx_local_assertion_authority_config);

  sgx::RemoteAssertionGeneratorEnclaveConfig *age_config =
      load_config.mutable_config()->MutableExtension(
          sgx::remote_assertion_generator_enclave_config);
  age_config->set_remote_assertion_generator_server_address(
      std::move(server_address));

  return load_config;
}

StatusOr<EnclaveClient *> SgxInfrastructuralEnclaveManager::GetAgeEnclaveClient(
    const EnclaveLoadConfig &load_config) {
  EnclaveManager *enclave_manager;
  ASYLO_ASSIGN_OR_RETURN(enclave_manager, EnclaveManager::Instance());
  ASYLO_RETURN_IF_ERROR(enclave_manager->LoadEnclave(load_config));
  return enclave_manager->GetClient(load_config.name());
}

StatusOr<Certificate> SgxInfrastructuralEnclaveManager::CertifyAge(
    const sgx::PceSvn &target_pce_svn, const sgx::CpuSvn &target_cpu_svn) {
  // Get the PCE's target info.
  sgx::TargetInfoProto pce_target_info;
  sgx::PceSvn pce_svn;
  ASYLO_RETURN_IF_ERROR(PceGetTargetInfo(&pce_target_info, &pce_svn));

  // Generate a new AGE key and a REPORT bound to that key.
  sgx::ReportProto report;
  std::string pce_sign_report_payload;
  sgx::TargetedCertificateSigningRequest unused_signing_request;
  ASYLO_RETURN_IF_ERROR(AgeGenerateKeyAndCsr(pce_target_info, &report,
                                             &pce_sign_report_payload,
                                             &unused_signing_request));

  // Certify key with the PCK at the selected PCESVN and selected CPUSVN.
  return CertifyAge(std::move(report), std::move(pce_sign_report_payload),
                    target_pce_svn, target_cpu_svn);
}

StatusOr<Certificate> SgxInfrastructuralEnclaveManager::CertifyAge() {
  // Get the PCE's target info.
  sgx::TargetInfoProto pce_target_info;
  sgx::PceSvn pce_svn;
  ASYLO_RETURN_IF_ERROR(PceGetTargetInfo(&pce_target_info, &pce_svn));

  // Fetch the platform's current CPUSVN from the AGE's identity.
  sgx::ReportProto report;
  std::string pce_sign_report_payload;
  sgx::TargetedCertificateSigningRequest unused_signing_request;
  ASYLO_RETURN_IF_ERROR(AgeGenerateKeyAndCsr(pce_target_info, &report,
                                             &pce_sign_report_payload,
                                             &unused_signing_request));

  SgxIdentity age_identity;
  ASYLO_ASSIGN_OR_RETURN(age_identity, AgeGetSgxIdentity());

  // Certify key with the PCK at the current CPUSVN and the current PCE SVN.
  return CertifyAge(std::move(report), std::move(pce_sign_report_payload),
                    pce_svn, age_identity.machine_configuration().cpu_svn());
}

StatusOr<Certificate> SgxInfrastructuralEnclaveManager::CertifyAge(
    sgx::ReportProto age_report, std::string pce_sign_report_payload,
    const sgx::PceSvn &target_pce_svn, const sgx::CpuSvn &target_cpu_svn) {
  Signature pck_signature;
  ASYLO_ASSIGN_OR_RETURN(
      pck_signature, PceSignReport(target_pce_svn, target_cpu_svn, age_report));

  Certificate attestation_key_certificate;
  ASYLO_ASSIGN_OR_RETURN(attestation_key_certificate,
                         sgx::CreateAttestationKeyCertificate(
                             std::move(age_report), std::move(pck_signature),
                             std::move(pce_sign_report_payload)));

  return attestation_key_certificate;
}

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
  return absl::OkStatus();
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
    const std::vector<asylo::CertificateChain> &cert_chains,
    bool validate_cert_chains) {
  EnclaveInput input;
  sgx::UpdateCertsInput *update_certs_input =
      input.MutableExtension(sgx::remote_assertion_generator_enclave_input)
          ->mutable_update_certs_input();
  *update_certs_input->mutable_certificate_chains() = {cert_chains.begin(),
                                                       cert_chains.end()};
  update_certs_input->set_output_sealed_secret(true);
  update_certs_input->set_validate_certificate_chains(validate_cert_chains);

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

StatusOr<SgxIdentity> SgxInfrastructuralEnclaveManager::AgeGetSgxIdentity() {
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

  return absl::OkStatus();
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

  return absl::OkStatus();
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
