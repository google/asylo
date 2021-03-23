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

#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_tool_lib.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "absl/base/call_once.h"
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/crypto/rsa_oaep_encryption_key.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/host_dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/internal/report_oracle_enclave_wrapper.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/ppid_ek.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client_impl.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/http_fetcher_impl.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(
    std::string, api_key, "",
    "(required) API key to authenticate to the Intel PCS. Get an API key by "
    "registering with Intel at "
    "https://api.portal.trustedservices.intel.com/provisioning-certification.");
ABSL_FLAG(
    std::string, ppid, "",
    "(required) The per-processor identifier, expressed as ASCII hexadeximal.");
ABSL_FLAG(std::string, cpu_svn, "",
          "(required) The CPU's secure version number, expressed as ASCII "
          "hexadecimal.");
ABSL_FLAG(int, pce_svn, asylo::sgx::kInvalidPceSvn,
          "(required) The PCE's secure version number.");
ABSL_FLAG(std::string, outfile, "certs.out",
          "The name of the file where the CertificateChain will be written.");
ABSL_FLAG(std::string, outfmt, "textproto",
          "The output format to use. Valid options are 'textproto' or 'pem'. "
          "Defaults to textproto.");

namespace asylo {
namespace sgx {
namespace {

// This certificate was pulled from the Chrome browser root certificate store.
constexpr char kCaCert[] =
    R"cert(-----BEGIN CERTIFICATE-----
MIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR
6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X
pz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC
9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV
/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf
Zd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z
+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w
qP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah
SL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC
u9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf
Fobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq
crxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E
FgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl
wFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM
4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV
2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna
FxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ
CuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK
boHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke
jkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL
S0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb
QOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl
0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB
NVOFBkpdn627G190
-----END CERTIFICATE-----)cert";

// Returns the path for a file containing the CA certificate used to
// authenticate the Intel PCS HTTPS server identity.
StatusOr<std::string> GetCertFilePath() {
  static char cert_filename[16] = "/tmp/certXXXXXX";
  static Status *status = nullptr;

  static absl::once_flag once_flag;
  absl::call_once(once_flag, [] {
    int fd = mkstemp(cert_filename);
    if (fd == -1) {
      status = new Status(LastPosixError("Error creating temp file"));
      return;
    }

    std::atexit([]() { unlink(cert_filename); });

    int write_result = write(fd, kCaCert, sizeof(kCaCert) - 1);
    close(fd);
    if (write_result == -1) {
      status = new Status(LastPosixError(
          absl::StrCat("Error writing cert temp file to ", cert_filename)));
    }
  });

  if (status != nullptr) {
    return *status;
  }

  return cert_filename;
}

Status WritePemCert(const Certificate &cert_proto, std::ofstream &output) {
  if (cert_proto.format() == Certificate::X509_PEM) {
    output << cert_proto.data();
    return absl::OkStatus();
  }

  std::unique_ptr<X509Certificate> cert;
  ASYLO_ASSIGN_OR_RETURN(cert, X509Certificate::Create(cert_proto));

  Certificate pem_cert_proto;
  ASYLO_ASSIGN_OR_RETURN(pem_cert_proto,
                         cert->ToCertificateProto(Certificate::X509_PEM));
  output << pem_cert_proto.data();
  return absl::OkStatus();
}

Status WritePemOutput(const GetPckCertificateResult &cert_result,
                      std::string filename) {
  std::ofstream output(filename);
  ASYLO_RETURN_IF_ERROR(WritePemCert(cert_result.pck_cert, output));
  for (auto &cert : cert_result.issuer_cert_chain.certificates()) {
    ASYLO_RETURN_IF_ERROR(WritePemCert(cert, output));
  }

  return absl::OkStatus();
}

Status WriteTextProtoOutput(asylo::sgx::GetPckCertificateResult cert_result,
                            std::string filename) {
  asylo::CertificateChain chain;
  *chain.add_certificates() = std::move(cert_result.pck_cert);
  for (auto &cert : cert_result.issuer_cert_chain.certificates()) {
    *chain.add_certificates() = std::move(cert);
  }

  int output_fd = creat(filename.c_str(), /*mode=*/0664);
  if (output_fd == -1) {
    return LastPosixError(absl::StrCat("Unable to open ", filename));
  }

  google::protobuf::io::FileOutputStream output(output_fd);
  google::protobuf::TextFormat::Print(chain, &output);

  return absl::OkStatus();
}

}  // namespace

void PlatformInfo::FillEmptyFields(const PlatformInfo &info) {
  if (!ppid.has_value()) {
    ppid = info.ppid;
  }

  if (!cpu_svn.has_value()) {
    cpu_svn = info.cpu_svn;
  }

  if (!pce_svn.has_value()) {
    pce_svn = info.pce_svn;
  }

  if (!pce_id.has_value()) {
    pce_id = info.pce_id;
  }
}

StatusOr<PlatformInfo> GetPlatformInfoFromFlags() {
  PlatformInfo info;

  std::string ppid_input = absl::GetFlag(FLAGS_ppid);
  if (!ppid_input.empty()) {
    info.ppid.set_value(absl::HexStringToBytes(ppid_input));
    ASYLO_RETURN_IF_ERROR(ValidatePpid(info.ppid));
  }

  std::string cpu_svn_input = absl::GetFlag(FLAGS_cpu_svn);
  if (!cpu_svn_input.empty()) {
    info.cpu_svn.set_value(absl::HexStringToBytes(cpu_svn_input));
    ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(info.cpu_svn));
  }

  int pce_svn_input = absl::GetFlag(FLAGS_pce_svn);
  if (pce_svn_input != kInvalidPceSvn) {
    info.pce_svn.set_value(pce_svn_input);
    ASYLO_RETURN_IF_ERROR(ValidatePceSvn(info.pce_svn));
  }

  info.pce_id.set_value(asylo::sgx::kSupportedPceId);
  return info;
}

StatusOr<PlatformInfo> GetPlatformInfoFromDcap(
    absl::string_view report_oracle_enclave_section_name) {
  std::unique_ptr<ReportOracleEnclaveWrapper> report_oracle;
  ASYLO_ASSIGN_OR_RETURN(report_oracle,
                         ReportOracleEnclaveWrapper::LoadFromSection(
                             report_oracle_enclave_section_name));

  // Get the info for targeting the PCE.
  DcapIntelArchitecturalEnclaveInterface dcap(
      absl::make_unique<HostDcapLibraryInterface>());
  Targetinfo targetinfo;
  uint16_t pce_svn;
  ASYLO_RETURN_IF_ERROR(dcap.GetPceTargetinfo(&targetinfo, &pce_svn));

  // Generate a key, the ask the oracle to build a report for it.
  std::unique_ptr<AsymmetricDecryptionKey> ppid_decryption_key;
  ASYLO_ASSIGN_OR_RETURN(ppid_decryption_key,
                         RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey(
                             HashAlgorithm::SHA256));

  std::unique_ptr<AsymmetricEncryptionKey> ppid_encryption_key;
  ASYLO_ASSIGN_OR_RETURN(ppid_encryption_key,
                         ppid_decryption_key->GetEncryptionKey());

  AsymmetricEncryptionKeyProto ppid_encryption_key_proto;
  ASYLO_ASSIGN_OR_RETURN(
      ppid_encryption_key_proto,
      ConvertToAsymmetricEncryptionKeyProto(*ppid_encryption_key));

  Reportdata reportdata;
  ASYLO_ASSIGN_OR_RETURN(
      reportdata, CreateReportdataForGetPceInfo(ppid_encryption_key_proto));

  Report report;
  ASYLO_ASSIGN_OR_RETURN(report,
                         report_oracle->GetReport(targetinfo, reportdata));

  // Send the report to the PCE, which will encrypt the PPID to the key that's
  // in the report data.
  std::vector<uint8_t> serialized_ppidek;
  ASYLO_ASSIGN_OR_RETURN(serialized_ppidek,
                         SerializePpidek(ppid_encryption_key_proto));

  std::string ppid_encrypted;
  uint16_t pce_id;
  SignatureScheme signature_scheme;
  ASYLO_RETURN_IF_ERROR(dcap.GetPceInfo(
      report, serialized_ppidek, ppid_decryption_key->GetEncryptionScheme(),
      &ppid_encrypted, &pce_svn, &pce_id, &signature_scheme));

  CleansingVector<uint8_t> ppid;
  ASYLO_RETURN_IF_ERROR(ppid_decryption_key->Decrypt(ppid_encrypted, &ppid));

  PlatformInfo info;
  info.pce_svn.set_value(pce_svn);
  info.pce_id.set_value(pce_id);
  info.cpu_svn.set_value(report.body.cpusvn.data(), report.body.cpusvn.size());
  info.ppid.set_value(ppid.data(), ppid.size());
  return info;
}

StatusOr<std::unique_ptr<SgxPcsClient>> CreateSgxPcsClientFromFlags() {
  std::string api_key = absl::GetFlag(FLAGS_api_key);
  if (api_key.empty()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat(FLAGS_api_key.Name(), " must be specified"));
  }

  std::unique_ptr<AsymmetricEncryptionKey> ppid_ek;
  ASYLO_ASSIGN_OR_RETURN(ppid_ek, asylo::RsaOaepEncryptionKey::CreateFromProto(
                                      GetPpidEkProto(), asylo::SHA256));

  std::string cert_file;
  ASYLO_ASSIGN_OR_RETURN(cert_file, GetCertFilePath());
  return SgxPcsClientImpl::Create(
      absl::make_unique<asylo::HttpFetcherImpl>(cert_file), std::move(ppid_ek),
      api_key);
}

Status WriteOutputAccordingToFlags(GetPckCertificateResult cert_result) {
  std::string outfmt = absl::GetFlag(FLAGS_outfmt);
  std::string outfile = absl::GetFlag(FLAGS_outfile);
  std::cout << "Writing the certificate chain to " << outfile << "."
            << std::endl;

  if (outfmt == "textproto") {
    return asylo::sgx::WriteTextProtoOutput(std::move(cert_result),
                                            std::move(outfile));
  }

  if (outfmt == "pem") {
    return asylo::sgx::WritePemOutput(std::move(cert_result),
                                      std::move(outfile));
  }

  return absl::InvalidArgumentError(
      absl::StrCat("Invalid ", FLAGS_outfmt.Name(), " value: ", outfmt));
}

}  // namespace sgx
}  // namespace asylo
