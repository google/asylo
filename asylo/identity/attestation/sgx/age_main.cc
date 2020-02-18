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

#include <memory>
#include <string>

#include <google/protobuf/repeated_field.h>
#include <google/protobuf/text_format.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "asylo/client.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/fake_pce.h"
#include "asylo/identity/attestation/sgx/internal/host_dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_test_util.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"
#include "asylo/identity/sgx/sgx_infrastructural_enclave_manager.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

//
// Option A: Run the Assertion Generator Enclave.
//

// Required for Option A.
ABSL_FLAG(bool, start_age, false,
          "Whether to start the AGE's attestation server");

// Required for Option A.
ABSL_FLAG(std::string, age_server_address,
          "unix:/tmp/assertion_generator_enclave",
          "The address to use for the AGE's attestation server");

ABSL_FLAG(absl::Duration, server_lifetime, absl::InfiniteDuration(),
          "The amount of time to run the AGE's attestation server before "
          "exiting");

ABSL_FLAG(bool, use_fake_pki, false,
          "Whether attestations should be rooted in the Asylo Fake PKI");

// Optional for Option A.
//
// This flag is ignored if --use_fake_pki is used.
ABSL_FLAG(asylo::CertificateChain, issuer_certificate_chain, {},
          "An X.509 issuer certificate chain for the PCK certificate provided "
          "to AGE");

// Optional for Option A.
ABSL_FLAG(std::string, intel_enclaves_path, "",
          "Path to the folder containing the libsgx_pce.signed.so binary");

// Required for Option A.
ABSL_FLAG(std::string, age_path, "", "Path to the AGE binary");

ABSL_FLAG(bool, is_debuggable_enclave, false,
          "Whether to run the AGE in debug mode");

namespace {

constexpr uint16_t kFakePceSvn = 7;

}  // namespace

namespace asylo {

bool AbslParseFlag(absl::string_view text, asylo::CertificateChain *flag,
                   std::string *error) {
  if (!google::protobuf::TextFormat::ParseFromString(
          std::string(text.data(), text.size()), flag)) {
    *error = "Failed to parse asylo::CertificateChain";
    return false;
  }
  return true;
}

std::string AbslUnparseFlag(const asylo::CertificateChain &flag) {
  std::string serialized_flag;
  CHECK(google::protobuf::TextFormat::PrintToString(flag, &serialized_flag));
  return serialized_flag;
}

}  // namespace asylo

namespace {

asylo::StatusOr<asylo::EnclaveClient *> GetAgeClient(
    std::string enclave_path, bool is_debuggable_enclave,
    std::string server_address) {
  asylo::EnclaveAssertionAuthorityConfig sgx_local_assertion_authority_config;
  ASYLO_ASSIGN_OR_RETURN(sgx_local_assertion_authority_config,
                         asylo::CreateSgxLocalAssertionAuthorityConfig());

  asylo::EnclaveLoadConfig load_config =
      asylo::SgxInfrastructuralEnclaveManager::GetAgeEnclaveLoadConfig(
          std::move(enclave_path), is_debuggable_enclave,
          std::move(server_address),
          std::move(sgx_local_assertion_authority_config));

  return asylo::SgxInfrastructuralEnclaveManager::GetAgeEnclaveClient(
      load_config);
}

}  // namespace

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  std::string age_path = absl::GetFlag(FLAGS_age_path);
  LOG_IF(QFATAL, age_path.empty()) << "--age_path cannot be empty";

  asylo::StatusOr<asylo::EnclaveClient *> client_result =
      GetAgeClient(age_path, absl::GetFlag(FLAGS_is_debuggable_enclave),
                   absl::GetFlag(FLAGS_age_server_address));
  LOG_IF(QFATAL, !client_result.ok())
      << "Failed to load AGE: " << client_result.status();

  std::unique_ptr<asylo::sgx::IntelArchitecturalEnclaveInterface>
      intel_enclaves;

  bool use_fake_pki = absl::GetFlag(FLAGS_use_fake_pki);

  if (use_fake_pki) {
    LOG(WARNING) << "Using Asylo Fake SGX PKI";

    auto result = asylo::sgx::FakePce::CreateFromFakePki(kFakePceSvn);
    LOG_IF(QFATAL, !result.ok())
        << "Failed to create FakePce: " << result.status();
    intel_enclaves = std::move(result).ValueOrDie();
  } else {
    intel_enclaves =
        absl::make_unique<asylo::sgx::DcapIntelArchitecturalEnclaveInterface>(
            absl::make_unique<asylo::sgx::HostDcapLibraryInterface>());
  }

  std::string intel_enclaves_path = absl::GetFlag(FLAGS_intel_enclaves_path);
  if (!intel_enclaves_path.empty()) {
    asylo::Status status = intel_enclaves->SetEnclaveDir(intel_enclaves_path);
    LOG_IF(QFATAL, !status.ok())
        << "Failed to set up Intel enclave dir: " << status;
  }

  std::unique_ptr<asylo::SgxInfrastructuralEnclaveManager>
      sgx_infra_enclave_manager =
          absl::make_unique<asylo::SgxInfrastructuralEnclaveManager>(
              std::move(intel_enclaves), client_result.ValueOrDie());

  if (absl::GetFlag(FLAGS_start_age)) {
    asylo::CertificateChain age_certificate_chain;

    auto attestation_key_certificate_result =
        sgx_infra_enclave_manager->CertifyAge();
    LOG_IF(QFATAL, !attestation_key_certificate_result.ok())
        << "Failed to certify AGE";

    *age_certificate_chain.add_certificates() =
        std::move(attestation_key_certificate_result).ValueOrDie();

    if (use_fake_pki) {
      asylo::sgx::AppendFakePckCertificateChain(&age_certificate_chain);
    } else if (!absl::GetFlag(FLAGS_issuer_certificate_chain)
                    .certificates()
                    .empty()) {
      asylo::CertificateChain certificate_chain =
          absl::GetFlag(FLAGS_issuer_certificate_chain);
      std::move(certificate_chain.certificates().begin(),
                certificate_chain.certificates().end(),
                google::protobuf::RepeatedFieldBackInserter(
                    age_certificate_chain.mutable_certificates()));
    }

    asylo::Status status =
        sgx_infra_enclave_manager->AgeUpdateCerts({age_certificate_chain})
            .status();
    LOG_IF(QFATAL, !status.ok()) << "Failed to update AGE certs: " << status;

    status = sgx_infra_enclave_manager->AgeStartServer();
    LOG_IF(QFATAL, !status.ok()) << "Failed to start AGE server: " << status;

    absl::SleepFor(absl::GetFlag(FLAGS_server_lifetime));
  }

  return 0;
}
