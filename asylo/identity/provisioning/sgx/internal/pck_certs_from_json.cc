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

#include "asylo/identity/provisioning/sgx/internal/pck_certs_from_json.h"

#include <endian.h>

#include <cstdint>
#include <cstring>
#include <functional>

#include "google/protobuf/struct.pb.h"
#include <google/protobuf/util/json_util.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb_info_from_json.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/function_deleter.h"
#include "asylo/util/hex_util.h"
#include "asylo/util/proto_struct_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/url_util.h"

namespace asylo {
namespace sgx {
namespace {

// Size of Provisioning Certification Enclave (PCE) Security Version
// Number (SVN) in bytes.
constexpr uint32_t kPcesvnSize = 2;

// Size of the RawTcb in bytes.
constexpr uint32_t kRawTcbSize = kCpusvnSize + kPcesvnSize;

// Parses a Certificate proto from JSON string |cert_json|.
StatusOr<Certificate> CertificateFromJsonValue(
    const google::protobuf::Value &cert_json) {
  const std::string *cert_str;
  ASYLO_ASSIGN_OR_RETURN(cert_str, JsonGetString(cert_json));
  std::string cert_str_unescaped;
  ASYLO_ASSIGN_OR_RETURN(cert_str_unescaped, UrlDecode(*cert_str));
  return GetCertificateFromPem(cert_str_unescaped);
}

// Parses a RawTcb proto from JSON string |raw_tcb_json|.
StatusOr<RawTcb> RawTcbFromJsonValue(
    const google::protobuf::Value &raw_tcb_json) {
  const std::string *raw_tcb_hex;
  ASYLO_ASSIGN_OR_RETURN(raw_tcb_hex, JsonGetString(raw_tcb_json));
  if (!IsHexEncoded(*raw_tcb_hex)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Raw TCB JSON is not a hex-encoded string.");
  }
  std::string raw_tcb = absl::HexStringToBytes(*raw_tcb_hex);
  if (raw_tcb.size() != kRawTcbSize) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Raw TCB JSON does not represents a ",
                               kRawTcbSize, "-byte value."));
  }
  RawTcb raw_tcb_proto;
  raw_tcb_proto.mutable_cpu_svn()->set_value(raw_tcb.data(), kCpusvnSize);
  raw_tcb_proto.mutable_pce_svn()->set_value(le16toh(
      *reinterpret_cast<const uint16_t *>(raw_tcb.data() + kCpusvnSize)));
  return raw_tcb_proto;
}

// Parses PckCertificateInfo proto from |pck_cert_json|.
StatusOr<PckCertificates::PckCertificateInfo> PckCertificateInfoFromJsonValue(
    const google::protobuf::Value &pck_cert_json) {
  const google::protobuf::Struct *pck_cert_object;
  ASYLO_ASSIGN_OR_RETURN(pck_cert_object, JsonGetObject(pck_cert_json));
  PckCertificates::PckCertificateInfo pck_cert_proto;

  const google::protobuf::Value *tcb_json;
  ASYLO_ASSIGN_OR_RETURN(tcb_json, JsonObjectGetField(*pck_cert_object, "tcb"));
  std::string tcb_json_str;
  ASYLO_RETURN_IF_ERROR(
      Status(google::protobuf::util::MessageToJsonString(*tcb_json, &tcb_json_str)));
  ASYLO_ASSIGN_OR_RETURN(*pck_cert_proto.mutable_tcb_level(),
                         TcbFromJson(tcb_json_str));

  const google::protobuf::Value *tcbm_json;
  ASYLO_ASSIGN_OR_RETURN(tcbm_json,
                         JsonObjectGetField(*pck_cert_object, "tcbm"));
  ASYLO_ASSIGN_OR_RETURN(*pck_cert_proto.mutable_tcbm(),
                         RawTcbFromJsonValue(*tcbm_json));

  const google::protobuf::Value *cert_json;
  ASYLO_ASSIGN_OR_RETURN(cert_json,
                         JsonObjectGetField(*pck_cert_object, "cert"));
  ASYLO_ASSIGN_OR_RETURN(*pck_cert_proto.mutable_cert(),
                         CertificateFromJsonValue(*cert_json));

  // We only expect three fields in |pck_cert_json|: "tcb", "tcbm", and "cert".
  // Log warning if there exist additional fields.
  if (pck_cert_object->fields().size() > 3) {
    std::string json_string;
    if (!google::protobuf::util::MessageToJsonString(pck_cert_json, &json_string).ok()) {
      json_string = "PCK Certificate JSON";
    }
    LOG(WARNING) << absl::StrCat("Encountered unrecognized fields in ",
                                 json_string);
  }
  return pck_cert_proto;
}

// Parses PckCertificates proto from |pck_certs_json|.
StatusOr<PckCertificates> PckCertificatesFromJsonValue(
    const google::protobuf::Value &pck_certs_json) {
  const google::protobuf::ListValue *pck_certs_array;
  ASYLO_ASSIGN_OR_RETURN(pck_certs_array, JsonGetArray(pck_certs_json));
  PckCertificates pck_certs;
  for (const auto &pck_cert_json : pck_certs_array->values()) {
    ASYLO_ASSIGN_OR_RETURN(*pck_certs.add_certs(),
                           PckCertificateInfoFromJsonValue(pck_cert_json));
  }
  return pck_certs;
}

}  // namespace

StatusOr<PckCertificates> PckCertificatesFromJson(const std::string &json_str) {
  google::protobuf::Value pck_certs_json;
  ASYLO_RETURN_IF_ERROR(
      Status(google::protobuf::util::JsonStringToMessage(json_str, &pck_certs_json)));
  return PckCertificatesFromJsonValue(pck_certs_json);
}

}  // namespace sgx
}  // namespace asylo
