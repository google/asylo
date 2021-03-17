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

#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client_impl.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certs_from_json.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/identity/provisioning/sgx/internal/signed_tcb_info_from_json.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/util/function_deleter.h"
#include "asylo/util/hex_util.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/url_util.h"
#include <curl/curl.h>

namespace asylo {
namespace sgx {
namespace {

// HTTP URL path of the Intel PCS APIs.
const char kPcsPath[] =
    "https://api.trustedservices.intel.com/sgx/certification/v1/";

// HTTP header name for the API key.
const char kHttpHeaderApiKey[] = "Ocp-Apim-Subscription-Key";

// HTTP header name for the PCK certificate issuer chain.
constexpr char kHttpHeaderPckCertIssuerCertChain[] =
    "SGX-PCK-Certificate-Issuer-Chain";

using FieldValueList = std::vector<std::pair<std::string, std::string>>;

// Creates a Url to query |path| with |command| and |arguments|.
//
// The following example creates the url
//     "https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?"
//     "encrypted_ppid=deadbeef&pceid=deadd00d":
//
//     std::string path =
//         "https://api.trustedservices.intel.com/sgx/certification/v1/";
//     std::string command = "pckcrl";
//     FieldValueList arguments = {{"encrypted_ppid", "deadbeef"},
//                                 {"pceid", "deadd00d"}};
//     std::string url = CreateUrl(path, command, arguments);
std::string CreateUrl(absl::string_view path, absl::string_view command,
                      const FieldValueList &arguments) {
  std::vector<std::string> formatted_arguments;
  formatted_arguments.reserve(arguments.size());
  std::transform(arguments.cbegin(), arguments.cend(),
                 std::back_inserter(formatted_arguments),
                 [](const std::pair<std::string, std::string> &fv) {
                   return absl::StrJoin({fv.first, fv.second}, "=");
                 });
  return absl::StrCat(path, command, "?",
                      absl::StrJoin(formatted_arguments, "&"));
}

// Parses the status code in |response| and returns a non-OK Status if the
// HTTP status code is not 200.
Status ParseHttpResponseError(const HttpFetcher::HttpResponse &response) {
  switch (response.status_code) {
    case 200:  // OK
      return absl::OkStatus();
    case 400:  // Bad Request
      return absl::InvalidArgumentError("Invalid request parameters");
    case 401:  // Unauthorized
      return absl::UnauthenticatedError(
          "Failed to authenticate or authorize the request");
    case 404:  // Not Found.
      return absl::NotFoundError("Requested resource cannot be found");
    case 500:  // Internal Server Error.
      return absl::InternalError("Internal server error occurred");
    case 503:  // Service Unavailable
      return absl::UnavailableError(
          "Server is currently unable to process the request");
    default:
      return absl::UnknownError(
          absl::StrCat("Unexpected HTTP status code ", response.status_code));
  }
}

// Returns the GetPckCertificateResult created by parsing |response|. Returns a
// non-OK Status upon parsing failure.
StatusOr<GetPckCertificateResult> ParseGetPckCertificateResponse(
    const HttpFetcher::HttpResponse &response) {
  constexpr char kHttpHeaderSgxTcbm[] = "SGX-TCBm";

  ASYLO_RETURN_IF_ERROR(ParseHttpResponseError(response));

  absl::optional<std::string> issuer_chain =
      response.GetHeaderValue(kHttpHeaderPckCertIssuerCertChain);
  if (!issuer_chain.has_value()) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("The reply header does not contain the ",
                               kHttpHeaderPckCertIssuerCertChain, " field"));
  }
  absl::optional<std::string> tcbm =
      response.GetHeaderValue(kHttpHeaderSgxTcbm);
  if (!tcbm.has_value()) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("The reply header does not contain the ",
                               kHttpHeaderSgxTcbm, " field"));
  }
  std::string issuer_chain_pem;
  ASYLO_ASSIGN_OR_RETURN(issuer_chain_pem, UrlDecode(*issuer_chain));
  GetPckCertificateResult result;
  ASYLO_ASSIGN_OR_RETURN(result.pck_cert, GetCertificateFromPem(response.body));
  ASYLO_ASSIGN_OR_RETURN(result.issuer_cert_chain,
                         GetCertificateChainFromPem(issuer_chain_pem));
  ASYLO_ASSIGN_OR_RETURN(result.tcbm, ParseRawTcbHex(*tcbm));
  return result;
}

// Returns the GetPckCertificatesResult created by parsing |response|. Returns a
// non-OK Status upon parsing failure.
StatusOr<GetPckCertificatesResult> ParseGetPckCertificatesResponse(
    const HttpFetcher::HttpResponse &response) {
  ASYLO_RETURN_IF_ERROR(ParseHttpResponseError(response));

  absl::optional<std::string> issuer_chain =
      response.GetHeaderValue(kHttpHeaderPckCertIssuerCertChain);
  if (!issuer_chain.has_value()) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("The reply header does not contain the ",
                               kHttpHeaderPckCertIssuerCertChain, " field"));
  }
  std::string issuer_chain_pem;
  ASYLO_ASSIGN_OR_RETURN(issuer_chain_pem, UrlDecode(*issuer_chain));
  GetPckCertificatesResult result;
  ASYLO_ASSIGN_OR_RETURN(result.pck_certs,
                         PckCertificatesFromJson(response.body));
  ASYLO_ASSIGN_OR_RETURN(result.issuer_cert_chain,
                         GetCertificateChainFromPem(issuer_chain_pem));
  return result;
}

// Returns the string that represents a |sgx_ca_type| according to Intel PCS
// API documentation. Returns an INVALID_ARGUMENT error if |sgx_ca_type| is
// SgxCaType_UNKNOWN.
StatusOr<std::string> CaTypeToStr(SgxCaType sgx_ca_type) {
  switch (sgx_ca_type) {
    case SgxCaType::PROCESSOR:
      return "processor";
    case SgxCaType::PLATFORM:
      return "platform";
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Input CA type cannot be unknown");
  }
}

// Returns the GetPckCrlResult created by parsing |response|. Returns a non-OK
// Status upon parsing failure.
StatusOr<GetCrlResult> ParseGetCrlResponse(
    const HttpFetcher::HttpResponse &response) {
  constexpr char kHttpHeaderIssuerCertChain[] = "SGX-PCK-CRL-Issuer-Chain";

  ASYLO_RETURN_IF_ERROR(ParseHttpResponseError(response));

  const absl::optional<std::string> issuer_chain =
      response.GetHeaderValue(kHttpHeaderIssuerCertChain);
  if (!issuer_chain.has_value()) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("The reply header does not contain the ",
                               kHttpHeaderIssuerCertChain, " field"));
  }
  std::string issuer_chain_pem;
  ASYLO_ASSIGN_OR_RETURN(issuer_chain_pem, UrlDecode(*issuer_chain));
  GetCrlResult result;
  ASYLO_ASSIGN_OR_RETURN(result.issuer_cert_chain,
                         GetCertificateChainFromPem(issuer_chain_pem));
  ASYLO_ASSIGN_OR_RETURN(result.pck_crl, GetCrlFromPem(response.body));
  return result;
}

// Returns the GetTcbInfoResult created by parsing |response|. Returns a non-OK
// Status upon parsing failure.
StatusOr<GetTcbInfoResult> ParseGetTcbInfoResponse(
    const HttpFetcher::HttpResponse &response) {
  constexpr char kHttpHeaderIssuerCertChain[] = "SGX-TCB-Info-Issuer-Chain";

  ASYLO_RETURN_IF_ERROR(ParseHttpResponseError(response));

  const absl::optional<std::string> issuer_chain =
      response.GetHeaderValue(kHttpHeaderIssuerCertChain);
  if (!issuer_chain.has_value()) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("The reply header does not contain the ",
                               kHttpHeaderIssuerCertChain, " field."));
  }
  std::string issuer_chain_pem;
  ASYLO_ASSIGN_OR_RETURN(issuer_chain_pem, UrlDecode(*issuer_chain));
  GetTcbInfoResult result;
  ASYLO_ASSIGN_OR_RETURN(result.issuer_cert_chain,
                         GetCertificateChainFromPem(issuer_chain_pem));
  ASYLO_ASSIGN_OR_RETURN(result.tcb_info, SignedTcbInfoFromJson(response.body));
  return result;
}

// Encrypts |ppid| using |enc_key| and returns the hex-encoded result. Return a
// non-OK Status if the encryption fails.
StatusOr<std::string> EncryptPpid(const AsymmetricEncryptionKey *enc_key,
                                  const Ppid &ppid) {
  if (enc_key == nullptr) {
    return Status(absl::StatusCode::kFailedPrecondition,
                  "No PPID encryption key provided");
  }
  std::vector<uint8_t> ppid_encrypted;
  ASYLO_RETURN_IF_ERROR(enc_key->Encrypt(ppid.value(), &ppid_encrypted));
  return absl::BytesToHexString(absl::string_view(
      reinterpret_cast<char *>(ppid_encrypted.data()), ppid_encrypted.size()));
}

}  // namespace

SgxPcsClientImpl::SgxPcsClientImpl(
    std::unique_ptr<HttpFetcher> fetcher,
    std::unique_ptr<AsymmetricEncryptionKey> ppid_enc_key,
    absl::string_view api_key)
    : fetcher_(std::move(CHECK_NOTNULL(fetcher))),
      ppid_enc_key_(std::move(ppid_enc_key)),
      api_key_(api_key) {}

StatusOr<std::unique_ptr<SgxPcsClient>> SgxPcsClientImpl::Create(
    std::unique_ptr<HttpFetcher> fetcher,
    std::unique_ptr<AsymmetricEncryptionKey> ppid_enc_key,
    absl::string_view api_key) {
  AsymmetricEncryptionScheme enc_scheme = ppid_enc_key->GetEncryptionScheme();
  if (enc_scheme != AsymmetricEncryptionScheme::RSA3072_OAEP) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrFormat(
                      "ppid_enc_key has an invalid encryption scheme: %s (%d). "
                      "Expected RSA3072_OAEP.",
                      ProtoEnumValueName(enc_scheme), enc_scheme));
  }
  // Using `new` to access a non-public constructor.
  return absl::WrapUnique(new SgxPcsClientImpl(
      std::move(fetcher), std::move(ppid_enc_key), api_key));
}

StatusOr<std::unique_ptr<SgxPcsClient>>
SgxPcsClientImpl::CreateWithoutPpidEncryptionKey(
    std::unique_ptr<HttpFetcher> fetcher, absl::string_view api_key) {
  // Using `new` to access a non-public constructor.
  return absl::WrapUnique(
      new SgxPcsClientImpl(std::move(fetcher), nullptr, api_key));
}

StatusOr<GetPckCertificateResult> SgxPcsClientImpl::GetPckCertificate(
    const Ppid &ppid, const CpuSvn &cpu_svn, const PceSvn &pce_svn,
    const PceId &pce_id) {
  ASYLO_RETURN_IF_ERROR(ValidatePpid(ppid));
  ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(cpu_svn));
  ASYLO_RETURN_IF_ERROR(ValidatePceSvn(pce_svn));
  ASYLO_RETURN_IF_ERROR(ValidatePceId(pce_id));
  std::string encrypted_ppid;
  ASYLO_ASSIGN_OR_RETURN(encrypted_ppid,
                         EncryptPpid(ppid_enc_key_.get(), ppid));
  std::string pce_svn_hex = Uint16ToLittleEndianHexString(pce_svn.value());
  std::string pce_id_hex = Uint16ToLittleEndianHexString(pce_id.value());
  const FieldValueList arguments = {
      {"encrypted_ppid", encrypted_ppid},
      {"cpusvn", absl::BytesToHexString(cpu_svn.value())},
      {"pcesvn", pce_svn_hex},
      {"pceid", pce_id_hex},
  };
  const std::string url_to_fetch =
      CreateUrl(kPcsPath, /*command=*/"pckcert", arguments);
  HttpFetcher::HttpResponse response;
  ASYLO_ASSIGN_OR_RETURN(response,
                         fetcher_->Get(url_to_fetch, /*custom_headers=*/{
                                           {kHttpHeaderApiKey, api_key_}}));
  return ParseGetPckCertificateResponse(response);
}

StatusOr<GetPckCertificatesResult> SgxPcsClientImpl::GetPckCertificates(
    const Ppid &ppid, const PceId &pce_id) {
  ASYLO_RETURN_IF_ERROR(ValidatePpid(ppid));
  ASYLO_RETURN_IF_ERROR(ValidatePceId(pce_id));
  std::string encrypted_ppid;
  ASYLO_ASSIGN_OR_RETURN(encrypted_ppid,
                         EncryptPpid(ppid_enc_key_.get(), ppid));
  const FieldValueList arguments = {
      {"encrypted_ppid", encrypted_ppid},
      {"pceid", Uint16ToLittleEndianHexString(pce_id.value())},
  };
  const std::string url_to_fetch = CreateUrl(kPcsPath,
                                             /*command=*/"pckcerts", arguments);
  HttpFetcher::HttpResponse response;
  ASYLO_ASSIGN_OR_RETURN(response,
                         fetcher_->Get(url_to_fetch, /*custom_headers=*/{
                                           {kHttpHeaderApiKey, api_key_}}));
  return ParseGetPckCertificatesResponse(response);
}

StatusOr<GetCrlResult> SgxPcsClientImpl::GetCrl(SgxCaType sgx_ca_type) {
  std::string ca_type_str;
  ASYLO_ASSIGN_OR_RETURN(ca_type_str, CaTypeToStr(sgx_ca_type));
  FieldValueList arguments = {{"ca", ca_type_str}};
  std::string url_to_fetch =
      CreateUrl(kPcsPath, /*command=*/"pckcrl", arguments);
  HttpFetcher::HttpResponse response;
  ASYLO_ASSIGN_OR_RETURN(response,
                         fetcher_->Get(url_to_fetch, /*custom_headers=*/{}));
  return ParseGetCrlResponse(response);
}

StatusOr<GetTcbInfoResult> SgxPcsClientImpl::GetTcbInfo(const Fmspc &fmspc) {
  ASYLO_RETURN_IF_ERROR(ValidateFmspc(fmspc));
  const FieldValueList arguments = {
      {"fmspc", absl::BytesToHexString(fmspc.value())},
  };
  const std::string url_to_fetch = CreateUrl(kPcsPath,
                                             /*command=*/"tcb", arguments);
  HttpFetcher::HttpResponse response;
  ASYLO_ASSIGN_OR_RETURN(response,
                         fetcher_->Get(url_to_fetch, /*custom_headers=*/{}));
  return ParseGetTcbInfoResponse(response);
}

}  // namespace sgx
}  // namespace asylo
