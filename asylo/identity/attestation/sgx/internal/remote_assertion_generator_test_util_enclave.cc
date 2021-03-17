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

#include <memory>

#include <google/protobuf/repeated_field.h>
#include "absl/status/status.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_test_util_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_client.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status_macros.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {
namespace sgx {
namespace {

Status GetRemoteAssertion(const GetRemoteAssertionInput &input,
                          GetRemoteAssertionOutput *output) {
  if (!input.has_server_address()) {
    return absl::InvalidArgumentError(
        "EnclaveConfig is missing server_address extension");
  }
  const std::string &server_address = input.server_address();
  LOG(INFO) << "Server address: " << server_address;

  // Make an RPC to the RemoteAssertionGenerator
  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());
  std::shared_ptr<::grpc::Channel> channel =
      ::grpc::CreateChannel(server_address, channel_credentials);

  SgxRemoteAssertionGeneratorClient client(channel);
  ASYLO_ASSIGN_OR_RETURN(*output->mutable_assertion(),
                         client.GenerateSgxRemoteAssertion("My User Data"));

  return absl::OkStatus();
}

Status GetTargetInfo(GetTargetInfoOutput *output) {
  AlignedTargetinfoPtr targetinfo;
  SetTargetinfoFromSelfIdentity(targetinfo.get());
  output->mutable_target_info_proto()->set_value(
      ConvertTrivialObjectToBinaryString(*targetinfo));
  return absl::OkStatus();
}

Status VerifyReport(const VerifyReportInput &input) {
  AlignedReportPtr report;
  ASYLO_ASSIGN_OR_RETURN(
      *report, ConvertReportProtoToHardwareReport(input.report_proto()));
  return VerifyHardwareReport(*report);
}

Status GetSealedSecret(const GetSealedSecretInput &input,
                       GetSealedSecretOutput *output) {
  SealedSecretHeader header = GetRemoteAssertionGeneratorEnclaveSecretHeader();
  std::unique_ptr<EcdsaP256Sha256SigningKey> attestation_key;
  ASYLO_ASSIGN_OR_RETURN(attestation_key, EcdsaP256Sha256SigningKey::Create());
  ASYLO_ASSIGN_OR_RETURN(*output->mutable_sealed_secret(),
                         CreateSealedSecret(header, input.certificate_chains(),
                                            *attestation_key.get()));
  return absl::OkStatus();
}

}  // namespace

class RemoteAssertionGeneratorTestUtilEnclave final
    : public TrustedApplication {
 public:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    if (!input.HasExtension(
            remote_assertion_generator_test_util_enclave_input)) {
      return absl::InvalidArgumentError(
          "EnclaveInput is missing "
          "RemoteAssertionGeneratorTestUtilEnclaveInput extension");
    }

    const RemoteAssertionGeneratorTestUtilEnclaveInput &enclave_input =
        input.GetExtension(remote_assertion_generator_test_util_enclave_input);
    RemoteAssertionGeneratorTestUtilEnclaveOutput *enclave_output =
        output->MutableExtension(
            remote_assertion_generator_test_util_enclave_output);

    switch (enclave_input.input_case()) {
      case RemoteAssertionGeneratorTestUtilEnclaveInput::
          kGetRemoteAssertionInput:
        return GetRemoteAssertion(
            enclave_input.get_remote_assertion_input(),
            enclave_output->mutable_get_remote_assertion_output());
      case RemoteAssertionGeneratorTestUtilEnclaveInput::kGetTargetInfoInput:
        return GetTargetInfo(enclave_output->mutable_get_target_info_output());
      case RemoteAssertionGeneratorTestUtilEnclaveInput::kVerifyReportInput:
        return VerifyReport(enclave_input.verify_report_input());
      case RemoteAssertionGeneratorTestUtilEnclaveInput::kGetSealedSecretInput:
        return GetSealedSecret(
            enclave_input.get_sealed_secret_input(),
            enclave_output->mutable_get_sealed_secret_output());
      default:
        return absl::InvalidArgumentError(
            "RemoteAssertionGeneratorTestUtilEnclaveInput not set");
    }
  }
};

}  // namespace sgx

TrustedApplication *BuildTrustedApplication() {
  return new sgx::RemoteAssertionGeneratorTestUtilEnclave();
}

}  // namespace asylo
