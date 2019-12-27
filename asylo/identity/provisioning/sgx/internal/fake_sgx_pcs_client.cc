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

#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pcs_client.h"

#include <endian.h>

#include <algorithm>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/struct.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/util/message_differencer.h>
#include "absl/base/attributes.h"
#include "absl/base/macros.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/distributions.h"
#include "absl/random/random.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/util/logging.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/time_conversions.h"

namespace asylo {
namespace sgx {
namespace {

// The FMSPC layout used by FakeSgxPcsClient. Used to determine the SGX CA
// corresponding to a given FMSPC.
struct FakeFmspcLayout {
  static constexpr int kCompressedSgxCaTypeBits = 2;

  // The SgxCaType that issues PCK certificates for platform instances with this
  // FMSPC.
  uint8_t ca : kCompressedSgxCaTypeBits;

  // Reserved for future use.
  uint16_t reserved : 8 * sizeof(uint16_t) - kCompressedSgxCaTypeBits;

  // The PCE ID corresponding to this FMSPC.
  uint16_t pce_id;

  // Random bytes. This field must be at least two bytes to ensure that the
  // probability of a collision in 10 random FMSPCs for a given
  // PlatformProperties is < 0.1%
  UnsafeBytes<2> random_id;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(FakeFmspcLayout) == kFmspcSize,
              "Invalid size for FakeFmspcLayout");
static_assert(1 << FakeFmspcLayout::kCompressedSgxCaTypeBits > SgxCaType_MAX,
              "FakeFmspcLayout::ca is too small to hold all SgxCaType values");

// Returns an error if |fmspc| is not valid according to ValidateFmspc() or does
// not match FakeFmspcLayout.
Status FmspcIsValidAndMatchesLayout(const Fmspc &fmspc) {
  ASYLO_RETURN_IF_ERROR(ValidateFmspc(fmspc));
  const FakeFmspcLayout *layout =
      reinterpret_cast<const FakeFmspcLayout *>(fmspc.value().data());
  if (!SgxCaType_IsValid(layout->ca) ||
      layout->ca == SgxCaType::SGX_CA_TYPE_UNKNOWN) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Invalid FMSPC: bad SgxCaType");
  }
  return Status::OkStatus();
}

// Returns a non-OK status if:
//
//   * |fmspc| is not valid.
//   * |fmspc| does not match FakeFmspcLayout.
//   * |tcb_info| is not valid.
//   * |tcb_info| has a |version| other than 2.
//   * The FMSPC and PCE ID in |tcb_info| do not match |fmspc|.
Status IsValidFmspcTcbInfoPair(const Fmspc &fmspc, const TcbInfo &tcb_info) {
  ASYLO_RETURN_IF_ERROR(FmspcIsValidAndMatchesLayout(fmspc));
  ASYLO_RETURN_IF_ERROR(ValidateTcbInfo(tcb_info));
  if (!google::protobuf::util::MessageDifferencer::Equals(tcb_info.impl().fmspc(),
                                                fmspc)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrFormat(
                      "TCB info is for wrong FMSPC: expected 0x%s, found 0x%s",
                      absl::BytesToHexString(fmspc.value()),
                      absl::BytesToHexString(tcb_info.impl().fmspc().value())));
  }
  const FakeFmspcLayout *layout =
      reinterpret_cast<const FakeFmspcLayout *>(fmspc.value().data());
  if (tcb_info.impl().pce_id().value() != layout->pce_id) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("TCB info is for wrong PCE ID: expected %d, found %d",
                        layout->pce_id, tcb_info.impl().pce_id().value()));
  }
  return Status::OkStatus();
}

// Fills |buffer| with random bytes.
void Randomize(absl::Span<uint8_t> buffer) {
  for (auto &byte : buffer) {
    byte = absl::Uniform(absl::BitGen(), 0, 256);
  }
}

// Creates a PEM-encoded X.509 certificate chain from |pem_certs|.
CertificateChain CreateCertificateChainFromPemCerts(
    const std::vector<absl::string_view> &pem_certs) {
  CertificateChain chain;
  for (absl::string_view pem : pem_certs) {
    Certificate *cert = chain.add_certificates();
    cert->set_format(Certificate::X509_PEM);
    cert->set_data(pem.data(), pem.size());
  }
  return chain;
}

// Converts a google::protobuf::Timestamp to an ISO 8601 timestamp string.
//
// This is used instead of google::protobuf::util::TimeUtil::ToString() because that
// function always adds a '.' after the seconds field, even if the nanoseconds
// field is zero. This reflects a difference betwen RFC 3339 and ISO 8601.
std::string GoogleTimestampToIso8601String(
    const google::protobuf::Timestamp &timestamp) {
  return absl::FormatTime("%Y-%m-%dT%H:%M:%SZ",
                          ConvertTime<absl::Time>(timestamp).ValueOrDie(),
                          absl::UTCTimeZone());
}

// Converts |tcb_info| to an Intel TCB info JSON structure with no whitespace.
// The |tcb_info| must be valid according to ValidateTcbInfo() and must have a
// |version| of 2.
StatusOr<std::string> TcbInfoToJson(const TcbInfo &tcb_info) {
  google::protobuf::Value tcb_info_json;
  auto *tcb_info_fields =
      tcb_info_json.mutable_struct_value()->mutable_fields();
  const TcbInfoImpl &impl = tcb_info.impl();
  google::protobuf::Value tcb_info_element;

  tcb_info_element.set_number_value(impl.version());
  tcb_info_fields->insert({"version", tcb_info_element});
  tcb_info_element.set_string_value(
      GoogleTimestampToIso8601String(impl.issue_date()));
  tcb_info_fields->insert({"issueDate", tcb_info_element});
  tcb_info_element.set_string_value(
      GoogleTimestampToIso8601String(impl.next_update()));
  tcb_info_fields->insert({"nextUpdate", tcb_info_element});
  tcb_info_element.set_string_value(
      absl::BytesToHexString(impl.fmspc().value()));
  tcb_info_fields->insert({"fmspc", tcb_info_element});
  uint16_t pce_id_little_endian = htole16(impl.pce_id().value());
  tcb_info_element.set_string_value(absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char *>(&pce_id_little_endian),
                        sizeof(pce_id_little_endian))));
  tcb_info_fields->insert({"pceId", tcb_info_element});
  if (impl.version() == 2) {
    tcb_info_element.set_number_value(impl.tcb_type());
    tcb_info_fields->insert({"tcbType", tcb_info_element});
    tcb_info_element.set_number_value(impl.tcb_evaluation_data_number());
    tcb_info_fields->insert({"tcbEvaluationDataNumber", tcb_info_element});
  }
  for (const TcbLevel &tcb_level : impl.tcb_levels()) {
    auto *tcb_level_fields = tcb_info_element.mutable_list_value()
                                 ->add_values()
                                 ->mutable_struct_value()
                                 ->mutable_fields();
    google::protobuf::Value tcb_level_element;

    auto *tcb_fields =
        tcb_level_element.mutable_struct_value()->mutable_fields();
    google::protobuf::Value tcb_element;
    for (int i = 0; i < kTcbComponentsSize; ++i) {
      tcb_element.set_number_value(tcb_level.tcb().components()[i]);
      tcb_fields->insert(
          {absl::StrFormat("sgxtcbcomp%02dsvn", i + 1), tcb_element});
    }
    tcb_element.set_number_value(tcb_level.tcb().pce_svn().value());
    tcb_fields->insert({"pcesvn", tcb_element});
    tcb_level_fields->insert({"tcb", tcb_level_element});

    std::string status_string;
    ASYLO_ASSIGN_OR_RETURN(status_string,
                           TcbStatusToString(tcb_level.status()));
    tcb_level_element.set_string_value(status_string);
    tcb_level_fields->insert(
        {impl.version() == 2 ? "tcbStatus" : "status", tcb_level_element});

    if (impl.version() == 2) {
      tcb_level_element.set_string_value(
          GoogleTimestampToIso8601String(tcb_level.tcb_date()));
      tcb_level_fields->insert({"tcbDate", tcb_level_element});

      if (!tcb_level.advisory_ids().empty()) {
        for (const std::string &advisory_id : tcb_level.advisory_ids()) {
          tcb_level_element.mutable_list_value()
              ->add_values()
              ->set_string_value(advisory_id);
        }
        tcb_level_fields->insert({"advisoryIDs", tcb_level_element});
      }
    }
  }
  tcb_info_fields->insert({"tcbLevels", tcb_info_element});

  std::string json;
  ASYLO_RETURN_IF_ERROR(
      Status(google::protobuf::util::MessageToJsonString(tcb_info_json, &json)));
  return json;
}

}  // namespace

FakeSgxPcsClient::FakeSgxPcsClient()
    : tcb_info_issuer_chain_(CreateCertificateChainFromPemCerts(
          {kFakeSgxTcbSigner.certificate_pem, kFakeSgxRootCa.certificate_pem})),
      tcb_info_signing_key_(std::move(EcdsaP256Sha256SigningKey::CreateFromPem(
                                          kFakeSgxTcbSigner.signing_key_pem))
                                .ValueOrDie()),
      tcb_infos_(FmspcToTcbInfoMap()) {}

StatusOr<bool> FakeSgxPcsClient::AddFmspc(Fmspc fmspc, TcbInfo tcb_info) {
  ASYLO_RETURN_IF_ERROR(IsValidFmspcTcbInfoPair(fmspc, tcb_info));
  return tcb_infos_.Lock()
      ->insert({std::move(fmspc), std::move(tcb_info)})
      .second;
}

Status FakeSgxPcsClient::UpdateFmspc(const Fmspc &fmspc, TcbInfo tcb_info) {
  ASYLO_RETURN_IF_ERROR(IsValidFmspcTcbInfoPair(fmspc, tcb_info));

  auto tcb_infos_view = tcb_infos_.Lock();
  auto it = tcb_infos_view->find(fmspc);
  if (it == tcb_infos_view->end()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("Unknown FMSPC: 0x",
                               absl::BytesToHexString(fmspc.value())));
  }
  it->second = std::move(tcb_info);
  return Status::OkStatus();
}

StatusOr<GetPckCertificateResult> FakeSgxPcsClient::GetPckCertificate(
    const Ppid &ppid, const CpuSvn &cpu_svn, const PceSvn &pce_svn,
    const PceId &pce_id) {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "FakeSgxPcsClient::GetPckCertificate() is not implemented");
}

StatusOr<GetPckCertificatesResult> FakeSgxPcsClient::GetPckCertificates(
    const Ppid &ppid, const PceId &pce_id) {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "FakeSgxPcsClient::GetPckCertificates() is not implemented");
}

StatusOr<GetCrlResult> FakeSgxPcsClient::GetCrl(SgxCaType sgx_ca_type) {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "FakeSgxPcsClient::GetCrl() is not implemented");
}

StatusOr<GetTcbInfoResult> FakeSgxPcsClient::GetTcbInfo(const Fmspc &fmspc) {
  ASYLO_RETURN_IF_ERROR(FmspcIsValidAndMatchesLayout(fmspc));

  GetTcbInfoResult result;
  result.issuer_cert_chain = tcb_info_issuer_chain_;

  TcbInfo tcb_info;
  {
    auto tcb_infos_readable_view = tcb_infos_.ReaderLock();
    auto it = tcb_infos_readable_view->find(fmspc);
    if (it == tcb_infos_readable_view->end()) {
      return Status(error::GoogleError::NOT_FOUND,
                    "No TCB info associated with given FMSPC");
    }

    tcb_info = it->second;
  }

  auto *impl = tcb_info.mutable_impl();
  absl::Time issue_date = absl::Now();
  *impl->mutable_issue_date() =
      ConvertTime<google::protobuf::Timestamp>(issue_date).ValueOrDie();
  absl::Time next_update = issue_date + absl::Hours(24 * 30);
  *impl->mutable_next_update() =
      ConvertTime<google::protobuf::Timestamp>(next_update).ValueOrDie();

  std::string tcb_info_json;
  ASYLO_ASSIGN_OR_RETURN(tcb_info_json, TcbInfoToJson(tcb_info));
  result.tcb_info.set_tcb_info_json(tcb_info_json);

  std::vector<uint8_t> signature;
  ASYLO_CHECK_OK(tcb_info_signing_key_->Sign(tcb_info_json, &signature));
  result.tcb_info.set_signature(signature.data(), signature.size());

  return result;
}

StatusOr<Fmspc> FakeSgxPcsClient::CreateFmspcWithProperties(
    const FakeSgxPcsClient::PlatformProperties &properties) {
  if (!SgxCaType_IsValid(properties.ca) ||
      properties.ca == SGX_CA_TYPE_UNKNOWN) {
    return Status(error::GoogleError::INVALID_ARGUMENT, "Invalid SgxCaType");
  }
  ASYLO_RETURN_IF_ERROR(ValidatePceId(properties.pce_id));

  FakeFmspcLayout layout = {};
  layout.ca = properties.ca;
  layout.pce_id = properties.pce_id.value();
  Randomize(absl::MakeSpan(layout.random_id));

  Fmspc fmspc;
  fmspc.set_value(&layout, sizeof(layout));
  return fmspc;
}

}  // namespace sgx
}  // namespace asylo
