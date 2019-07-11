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

#include "asylo/identity/sgx/remote_assertion_generator_enclave.h"

#include "asylo/crypto/keys.pb.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/sgx/remote_assertion_generator_enclave_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {

RemoteAssertionGeneratorEnclave::RemoteAssertionGeneratorEnclave()
    : attestation_key_certs_pair_(AttestationKeyCertsPair()),
      server_service_pair_(ServerServicePair()) {}

Status RemoteAssertionGeneratorEnclave::Initialize(
    const EnclaveConfig &config) {
  // Validate the enclave config.
  if (!config.HasExtension(remote_assertion_generator_enclave_config)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "EnclaveConfig is missing server_address field");
  }
  remote_assertion_generator_server_address_ =
      config.GetExtension(remote_assertion_generator_enclave_config)
          .remote_assertion_generator_server_address();
  if (remote_assertion_generator_server_address_.empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "EnclaveConfig does not include a server address");
  }
  return Status::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::Run(const EnclaveInput &input,
                                            EnclaveOutput *output) {
  if (!input.HasExtension(remote_assertion_generator_enclave_input)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "EnclaveInput format is not valid");
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
      return GeneratePceInfoHardwareReport(
          enclave_input.generate_pce_info_sgx_hardware_report_input(),
          enclave_output
              ->mutable_generate_pce_info_sgx_hardware_report_output());
    case RemoteAssertionGeneratorEnclaveInput::kGenerateKeyAndCsrRequestInput:
      return GenerateKeyAndCsr(
          enclave_input.generate_key_and_csr_request_input(),
          enclave_output->mutable_generate_key_and_csr_request_output());
    case RemoteAssertionGeneratorEnclaveInput::kUpdateCertsInput:
      return UpdateCerts(enclave_input.update_certs_input(),
                         enclave_output->mutable_update_certs_output());
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
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
  return Status::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::StartRemoteAssertionGeneratorGrpcServer(
    const StartServerRequestInput &input) {
  auto server_service_pair_locked = server_service_pair_.Lock();
  auto attestation_key_certs_pair_locked = attestation_key_certs_pair_.Lock();

  if (server_service_pair_locked->server) {
    return Status(error::GoogleError::ALREADY_EXISTS,
                  "Cannot start remote assertion generator gRPC server: server "
                  "already exits");
  }

  if (input.has_sealed_secret()) {
    ASYLO_ASSIGN_OR_RETURN(
        attestation_key_certs_pair_locked->attestation_key,
        ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
            input.sealed_secret(),
            &attestation_key_certs_pair_locked->certificate_chains));
    server_service_pair_locked->service = nullptr;
  } else if (!server_service_pair_locked->service &&
             !attestation_key_certs_pair_locked->attestation_key) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Cannot start remote assertion generator gRPC server: no "
                  "attestation key available");
  }

  if (!server_service_pair_locked->service) {
    server_service_pair_locked->service =
        absl::make_unique<SgxRemoteAssertionGeneratorImpl>(
            std::move(attestation_key_certs_pair_locked->attestation_key),
            attestation_key_certs_pair_locked->certificate_chains);
  }

  ASYLO_ASSIGN_OR_RETURN(
      server_service_pair_locked->server,
      CreateAndStartServer(remote_assertion_generator_server_address_,
                           server_service_pair_locked->service.get()));
  return Status::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::GeneratePceInfoHardwareReport(
    const GeneratePceInfoSgxHardwareReportInput &input,
    GeneratePceInfoSgxHardwareReportOutput *output) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

Status RemoteAssertionGeneratorEnclave::GenerateKeyAndCsr(
    const GenerateKeyAndCsrRequestInput &input,
    GenerateKeyAndCsrRequestOutput *output) {
  auto attestation_key_certs_pair_locked = attestation_key_certs_pair_.Lock();

  ASYLO_ASSIGN_OR_RETURN(attestation_key_certs_pair_locked->attestation_key,
                         EcdsaP256Sha256SigningKey::Create());

  return Status::OkStatus();
}

Status RemoteAssertionGeneratorEnclave::UpdateCerts(
    const UpdateCertsInput &input, UpdateCertsOutput *output) {
  auto attestation_key_certs_pair_locked = attestation_key_certs_pair_.Lock();

  if (!attestation_key_certs_pair_locked->attestation_key) {
    return Status(error::GoogleError::FAILED_PRECONDITION,
                  "Cannot update certificates: no attestation key available");
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
  return Status::OkStatus();
}

}  // namespace sgx

TrustedApplication *BuildTrustedApplication() {
  return new sgx::RemoteAssertionGeneratorEnclave();
}

}  // namespace asylo
