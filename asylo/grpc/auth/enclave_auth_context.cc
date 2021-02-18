/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/grpc/auth/enclave_auth_context.h"

#include <google/protobuf/io/coded_stream.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/grpc/auth/core/enclave_grpc_security_constants.h"
#include "asylo/identity/identity_acl_evaluator.h"
#include "asylo/util/status.h"
#include "src/core/lib/security/context/security_context.h"
#include "src/core/tsi/transport_security_interface.h"

namespace asylo {

StatusOr<EnclaveAuthContext> EnclaveAuthContext::CreateFromServerContext(
    const ::grpc::ServerContext &server_context) {
  return CreateFromAuthContext(*server_context.auth_context());
}

StatusOr<EnclaveAuthContext> EnclaveAuthContext::CreateFromAuthContext(
    const ::grpc::AuthContext &auth_context) {
  if (!auth_context.IsPeerAuthenticated()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Peer is not authenticated");
  }

  EnclaveIdentities identities;
  uint32_t record_protocol = 0;
  for (auto it = auth_context.begin(); it != auth_context.end(); ++it) {
    ::grpc::AuthProperty auth_property = *it;

    if (auth_property.first == GRPC_TRANSPORT_SECURITY_LEVEL_PROPERTY_NAME) {
      if (auth_property.second !=
          tsi_security_level_to_string(TSI_PRIVACY_AND_INTEGRITY)) {
        return Status(absl::StatusCode::kInvalidArgument,
                      absl::StrCat("Invalid transport security level: ",
                                   std::string(auth_property.second.data(),
                                               auth_property.second.size()),
                                   "; expected ",
                                   tsi_security_level_to_string(
                                       TSI_PRIVACY_AND_INTEGRITY)));
      }
    } else if (auth_property.first ==
               GRPC_ENCLAVE_RECORD_PROTOCOL_PROPERTY_NAME) {
      google::protobuf::io::CodedInputStream::ReadLittleEndian32FromArray(
          reinterpret_cast<const uint8_t *>(auth_property.second.data()),
          &record_protocol);
    } else if (auth_property.first ==
               auth_context.GetPeerIdentityPropertyName()) {
      if (!identities.ParseFromArray(auth_property.second.data(),
                                     auth_property.second.length())) {
        return Status(absl::StatusCode::kInvalidArgument,
                      "Ill-formed peer identity in auth context");
      }
    } else if (auth_property.first ==
               GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME) {
      if (auth_property.second != GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE) {
        return Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("Invalid transport security type: ",
                         std::string(auth_property.second.data(),
                                     auth_property.second.size()),
                         "; expected ", GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE));
      }
    } else {
      std::string auth_property_name =
          std::string(auth_property.first.data(), auth_property.first.length());
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unrecognized AuthProperty: ", auth_property_name));
    }
  }

  return EnclaveAuthContext(std::move(identities),
                            static_cast<RecordProtocol>(record_protocol));
}

EnclaveAuthContext::EnclaveAuthContext(EnclaveIdentities identities,
                                       RecordProtocol record_protocol)
    : identities_(
          {identities.identities().begin(), identities.identities().end()}),
      record_protocol_(record_protocol) {}

RecordProtocol EnclaveAuthContext::GetRecordProtocol() const {
  return record_protocol_;
}

bool EnclaveAuthContext::HasEnclaveIdentity(
    const EnclaveIdentityDescription &description) const {
  return FindEnclaveIdentity(description).ok();
}

StatusOr<const EnclaveIdentity *> EnclaveAuthContext::FindEnclaveIdentity(
    const EnclaveIdentityDescription &description) const {
  auto it =
      std::find_if(identities_.cbegin(), identities_.cend(),
                   [&description](const EnclaveIdentity &identity) -> bool {
                     return identity.description().identity_type() ==
                                description.identity_type() &&
                            identity.description().authority_type() ==
                                description.authority_type();
                   });
  if (it == identities_.cend()) {
    return Status(absl::StatusCode::kNotFound, "No matching identity");
  }
  return &*it;
}

StatusOr<bool> EnclaveAuthContext::EvaluateAcl(
    const IdentityAclPredicate &acl) const {
  return EvaluateAcl(acl, /*explanation=*/nullptr);
}

StatusOr<bool> EnclaveAuthContext::EvaluateAcl(const IdentityAclPredicate &acl,
                                               std::string *explanation) const {
  return EvaluateIdentityAcl(identities_, acl, matcher_,
                             /*explanation=*/explanation);
}

StatusOr<bool> EnclaveAuthContext::EvaluateAcl(
    const EnclaveIdentityExpectation &expectation) const {
  return EvaluateAcl(expectation, /*explanation=*/nullptr);
}

StatusOr<bool> EnclaveAuthContext::EvaluateAcl(
    const EnclaveIdentityExpectation &expectation,
    std::string *explanation) const {
  IdentityAclPredicate acl;
  *acl.mutable_expectation() = expectation;
  return EvaluateAcl(acl, explanation);
}

}  // namespace asylo
