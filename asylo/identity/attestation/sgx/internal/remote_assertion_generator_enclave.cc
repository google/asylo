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

#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/sgx/internal/certificate_util.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_util.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {

RemoteAssertionGeneratorEnclave::RemoteAssertionGeneratorEnclave()
    : attestation_key_certs_pair_(AttestationKeyCertsPair()),
      server_service_pair_(ServerServicePair()),
      verification_config_(/*all_fields=*/true) {}

Status RemoteAssertionGeneratorEnclave::Initialize(
    const EnclaveConfig &config) {
  // Validate the enclave config.
  if (!config.HasExtension(remote_assertion_generator_enclave_config)) {
    return absl::InvalidArgumentError(
        "EnclaveConfig is missing server_address field");
  }
  remote_assertion_generator_server_address_ =
      config.GetExtension(remote_assertion_generator_enclave_config)
          .remote_assertion_generator_server_address();
  if (remote_assertion_generator_server_address_.empty()) {
    return absl::InvalidArgumentError(
        "EnclaveConfig does not include a server address");
  }
  return absl::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::Run(const EnclaveInput &input,
                                            EnclaveOutput *output) {
  if (!input.HasExtension(remote_assertion_generator_enclave_input)) {
    return absl::InvalidArgumentError("EnclaveInput format is not valid");
  }
  const RemoteAssertionGeneratorEnclaveInput &enclave_input =
      input.GetExtension(remote_assertion_generator_enclave_input);
  RemoteAssertionGeneratorEnclaveOutput *enclave_output =
      output->MutableExtension(remote_assertion_generator_enclave_output);

  switch (enclave_input.input_case()) {
    case RemoteAssertionGeneratorEnclaveInput::kStartServerRequestInput:
      return StartRemoteAssertionGeneratorGrpcServer(
          enclave_input.start_server_request_input());
    case RemoteAssertionGeneratorEnclaveInput::
        kGeneratePceInfoSgxHardwareReportInput:
      return GeneratePceInfoSgxHardwareReport(
          enclave_input.generate_pce_info_sgx_hardware_report_input(),
          enclave_output
              ->mutable_generate_pce_info_sgx_hardware_report_output());
    case RemoteAssertionGeneratorEnclaveInput::kGenerateKeyAndCsrInput:
      return GenerateKeyAndCsr(
          enclave_input.generate_key_and_csr_input(),
          enclave_output->mutable_generate_key_and_csr_output());
    case RemoteAssertionGeneratorEnclaveInput::kUpdateCertsInput:
      return UpdateCerts(enclave_input.update_certs_input(),
                         enclave_output->mutable_update_certs_output());
    case RemoteAssertionGeneratorEnclaveInput::kGetEnclaveIdentityInput:
      SetSelfSgxIdentity(enclave_output->mutable_get_enclave_identity_output()
                             ->mutable_sgx_identity());
      return absl::OkStatus();
    default:
      return absl::InvalidArgumentError(
          "EnclaveInput invalid: did not contain a valid input");
  }
}

Status RemoteAssertionGeneratorEnclave::Finalize(
    const EnclaveFinal &final_input) {
  auto server_service_pair_locked = server_service_pair_.Lock();

  if (server_service_pair_locked->server) {
    server_service_pair_locked->server->Shutdown();
    server_service_pair_locked->server = nullptr;
  }
  return absl::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::StartRemoteAssertionGeneratorGrpcServer(
    const StartServerRequestInput &input) {
  auto server_service_pair_locked = server_service_pair_.Lock();
  auto attestation_key_certs_pair_locked = attestation_key_certs_pair_.Lock();

  if (server_service_pair_locked->server) {
    return absl::AlreadyExistsError(
        "Cannot start remote assertion generator gRPC server: server "
        "already exists");
  }

  if (input.has_sealed_secret()) {
    ASYLO_ASSIGN_OR_RETURN(
        attestation_key_certs_pair_locked->attestation_key,
        ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
            input.sealed_secret(),
            &attestation_key_certs_pair_locked->certificate_chains));
    server_service_pair_locked->service = nullptr;
  }

  if (!server_service_pair_locked->service) {
    server_service_pair_locked->service =
        attestation_key_certs_pair_locked->attestation_key == nullptr
            ? absl::make_unique<SgxRemoteAssertionGeneratorImpl>()
            : absl::make_unique<SgxRemoteAssertionGeneratorImpl>(
                  std::move(attestation_key_certs_pair_locked->attestation_key),
                  attestation_key_certs_pair_locked->certificate_chains);
  }

  ASYLO_ASSIGN_OR_RETURN(
      server_service_pair_locked->server,
      CreateAndStartServer(remote_assertion_generator_server_address_,
                           server_service_pair_locked->service.get()));
  return absl::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::GeneratePceInfoSgxHardwareReport(
    const GeneratePceInfoSgxHardwareReportInput &input,
    GeneratePceInfoSgxHardwareReportOutput *output) {
  if (!input.has_pce_target_info()) {
    return absl::InvalidArgumentError("Input is missing pce_target_info");
  }
  if (!input.has_ppid_encryption_key()) {
    return absl::InvalidArgumentError("Input is missing ppid_encryption_key");
  }
  AlignedReportdataPtr reportdata;
  ASYLO_ASSIGN_OR_RETURN(
      *reportdata, CreateReportdataForGetPceInfo(input.ppid_encryption_key()));
  AlignedTargetinfoPtr targetinfo;
  ASYLO_ASSIGN_OR_RETURN(
      *targetinfo, ConvertTargetInfoProtoToTargetinfo(input.pce_target_info()));

  Report report;
  ASYLO_ASSIGN_OR_RETURN(report, HardwareInterface::CreateDefault()->GetReport(
                                     *targetinfo, *reportdata));
  output->mutable_report()->set_value(
      ConvertTrivialObjectToBinaryString(report));

  return absl::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::GenerateKeyAndCsr(
    const GenerateKeyAndCsrInput &input, GenerateKeyAndCsrOutput *output) {
  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key;
  ASYLO_ASSIGN_OR_RETURN(signing_key, EcdsaP256Sha256SigningKey::Create());
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSIGN_OR_RETURN(verifying_key, signing_key->GetVerifyingKey());

  if (input.has_pce_target_info()) {
    ASYLO_ASSIGN_OR_RETURN(
        *output->mutable_pce_sign_report_payload(),
        CreateSerializedPceSignReportPayloadFromVerifyingKey(*verifying_key));

    AlignedReportdataPtr reportdata;
    ASYLO_ASSIGN_OR_RETURN(*reportdata,
                           GenerateReportdataForPceSignReportProtocol(
                               output->pce_sign_report_payload()));
    AlignedTargetinfoPtr targetinfo;
    ASYLO_ASSIGN_OR_RETURN(*targetinfo, ConvertTargetInfoProtoToTargetinfo(
                                            input.pce_target_info()));
    Report report;
    ASYLO_ASSIGN_OR_RETURN(
        report, HardwareInterface::CreateDefault()->GetReport(*targetinfo,
                                                              *reportdata));
    output->mutable_report()->set_value(
        ConvertTrivialObjectToBinaryString(report));
  }

  auto attestation_key_certs_pair_locked = attestation_key_certs_pair_.Lock();
  attestation_key_certs_pair_locked->attestation_key = std::move(signing_key);
  return absl::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::UpdateCerts(
    const UpdateCertsInput &input, UpdateCertsOutput *output) {
  auto server_service_pair_locked = server_service_pair_.Lock();
  auto attestation_key_certs_pair_locked = attestation_key_certs_pair_.Lock();
  if (!attestation_key_certs_pair_locked->attestation_key) {
    return absl::FailedPreconditionError(
        "Cannot update certificates: no attestation key available");
  }

  std::unique_ptr<VerifyingKey> attestation_public_key;
  ASYLO_ASSIGN_OR_RETURN(
      attestation_public_key,
      attestation_key_certs_pair_locked->attestation_key->GetVerifyingKey());

  if (input.validate_certificate_chains()) {
    // Verify that all certificate chains are valid and that they certify the
    // current attestation key before saving them.
    ASYLO_RETURN_IF_ERROR(
        WithContext(CheckCertificateChainsForAttestationPublicKey(
                        *attestation_public_key, input.certificate_chains(),
                        *GetSgxCertificateFactories(), verification_config_),
                    "Cannot update certificates"));
  }

  if (input.output_sealed_secret()) {
    SealedSecretHeader header =
        GetRemoteAssertionGeneratorEnclaveSecretHeader();
    ASYLO_ASSIGN_OR_RETURN(
        *output->mutable_sealed_secret(),
        CreateSealedSecret(
            header, input.certificate_chains(),
            *attestation_key_certs_pair_locked->attestation_key));
  }

  attestation_key_certs_pair_locked->certificate_chains = {
      input.certificate_chains().cbegin(), input.certificate_chains().cend()};
  if (server_service_pair_locked->service) {
    server_service_pair_locked->service->UpdateSigningKeyAndCertificateChains(
        std::move(attestation_key_certs_pair_locked->attestation_key),
        attestation_key_certs_pair_locked->certificate_chains);
  }
  return absl::OkStatus();
}

}  // namespace sgx

TrustedApplication *BuildTrustedApplication() {
  return new sgx::RemoteAssertionGeneratorEnclave();
}

}  // namespace asylo
