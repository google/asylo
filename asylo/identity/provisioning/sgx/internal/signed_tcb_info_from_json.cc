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

#include "asylo/identity/provisioning/sgx/internal/signed_tcb_info_from_json.h"

#include <string>
#include <utility>

#include "google/protobuf/struct.pb.h"
#include <google/protobuf/util/json_util.h>
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_replace.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/hex_util.h"
#include "asylo/util/proto_struct_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "re2/re2.h"

namespace asylo {
namespace sgx {
namespace {

// Regexpr to match the signed TCB info JSON where the "signature" field comes
// after the "tcbInfo" field.
static const LazyRE2 kSignedTcbInfoJsonSigLastPattern = {
    R"regexp((?s:\s*\{\s*\"tcbInfo\"\s*:\s*(\{.*\})\s*,\s*\"signature\"\s*:\s*\"[\d|a-f|A-F]*\"\s*\}\s*))regexp"};

// Regexpr to match the signed TCB info JSON where the "signature" field is
// ahead of the "tcbInfo" field.
static const LazyRE2 kSignedTcbInfoJsonSigFirstPattern = {
    R"regexp((?s:\s*\{\s*\"signature\"\s*:\s*\"[\d|a-f|A-F]*\"\s*,\s*\"tcbInfo\"\s*:\s*(\{.*\})\s*\}\s*))regexp"};

// Parses JSON string |signed_tcb_info_json| and populates |tcb_info_json| and
// |signature| with the values of "tcbInfo" and "signature" respectively.
// Returns an error status if the |signed_tcb_info_json| does not match
// the "TcbInfo" returned by Intel's Get TCB Info API (as documented at
// https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info).
Status ParseSignedTcbInfoFromJson(const std::string &signed_tcb_info_json,
                                  std::string *tcb_info_json,
                                  std::string *signature) {
  google::protobuf::Value signed_tcb_info_value;
  ASYLO_RETURN_IF_ERROR(Status(google::protobuf::util::JsonStringToMessage(
      signed_tcb_info_json, &signed_tcb_info_value)));
  const google::protobuf::Struct *signed_tcb_info_obj;
  ASYLO_ASSIGN_OR_RETURN(signed_tcb_info_obj,
                         JsonGetObject(signed_tcb_info_value));
  const google::protobuf::Value *sig_value;
  ASYLO_ASSIGN_OR_RETURN(sig_value,
                         JsonObjectGetField(*signed_tcb_info_obj, "signature"));
  const std::string *signature_str;
  ASYLO_ASSIGN_OR_RETURN(signature_str, JsonGetString(*sig_value));

  // Check that the signature is hex-encoded.
  if (!IsHexEncoded(*signature)) {
    return absl::InvalidArgumentError("Signature is not hex-encoded");
  }

  // The entire JSON was validated above, so it is safe to use regex to extract
  // the contents of the tcbInfo JSON field as a JSON string.
  if (!RE2::FullMatch(signed_tcb_info_json, *kSignedTcbInfoJsonSigLastPattern,
                      tcb_info_json) &&
      !RE2::FullMatch(signed_tcb_info_json, *kSignedTcbInfoJsonSigFirstPattern,
                      tcb_info_json)) {
    return absl::InvalidArgumentError(
        "Cannot parse the JSON of signed TCB info");
  }

  // According to Intel's Get TCB Info API documentation, the signature is
  // over the "tcbInfo" field without whitespaces.
  RE2::GlobalReplace(tcb_info_json, R"regexp(\s)regexp", "");
  *signature = *signature_str;
  return absl::OkStatus();
}

}  // namespace

StatusOr<SignedTcbInfo> SignedTcbInfoFromJson(const std::string &json_string) {
  std::string tcb_info_json;
  std::string signature_hex;
  ASYLO_RETURN_IF_ERROR(
      ParseSignedTcbInfoFromJson(json_string, &tcb_info_json, &signature_hex));

  SignedTcbInfo signed_tcb_info_proto;
  signed_tcb_info_proto.set_tcb_info_json(std::move(tcb_info_json));
  signed_tcb_info_proto.set_signature(absl::HexStringToBytes(signature_hex));
  return signed_tcb_info_proto;
}

}  // namespace sgx
}  // namespace asylo
