/*
 *
 * Copyright 2018 Asylo authors
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
#include "asylo/grpc/auth/peer_identity_util.h"

#include "absl/strings/str_cat.h"
#include "asylo/grpc/auth/enclave_auth_context.h"
#include "asylo/identity/delegating_identity_expectation_matcher.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

Status ExtractAndCheckPeerSgxCodeIdentity(const ::grpc::AuthContext &context,
                                          sgx::CodeIdentity *code_identity) {
  StatusOr<EnclaveAuthContext> auth_context_result =
      EnclaveAuthContext::CreateFromAuthContext(context);
  if (!auth_context_result.ok()) {
    LOG(ERROR) << "CreateFromServerContext failed: "
               << auth_context_result.status();
    return Status(error::GoogleError::INTERNAL,
                  "Failed to retrieve enclave authentication information");
  }

  EnclaveAuthContext auth_context = auth_context_result.ValueOrDie();
  EnclaveIdentityDescription code_identity_description;
  SetSgxIdentityDescription(&code_identity_description);
  StatusOr<const EnclaveIdentity *> identity_result =
      auth_context.FindEnclaveIdentity(code_identity_description);
  if (!identity_result.ok()) {
    LOG(ERROR) << "FindEnclaveIdentity failed: " << identity_result.status();
    return Status(error::GoogleError::PERMISSION_DENIED,
                  "Peer does not have SGX code identity");
  }
  return sgx::ParseSgxIdentity(*identity_result.ValueOrDie(), code_identity);
}

StatusOr<bool> ExtractAndMatchEnclaveIdentity(
    const ::grpc::AuthContext &context,
    const EnclaveIdentityExpectation &identity_expectation) {
  StatusOr<EnclaveAuthContext> auth_context_result =
      EnclaveAuthContext::CreateFromAuthContext(context);
  if (!auth_context_result.ok()) {
    LOG(ERROR) << "CreateFromServerContext failed: "
               << auth_context_result.status();
    return Status(error::GoogleError::INTERNAL,
                  "Failed to retrieve enclave authentication information");
  }

  EnclaveAuthContext auth_context = auth_context_result.ValueOrDie();
  DelegatingIdentityExpectationMatcher matcher;
  return ExtractAndMatchEnclaveIdentity(auth_context, identity_expectation,
                                        matcher);
}

StatusOr<bool> ExtractAndMatchEnclaveIdentity(
    const EnclaveAuthContext &enclave_auth_context,
    const EnclaveIdentityExpectation &identity_expectation,
    const IdentityExpectationMatcher &identity_expectation_matcher) {
  EnclaveIdentityDescription identity_description =
      identity_expectation.reference_identity().description();
  StatusOr<const EnclaveIdentity *> identity_result =
      enclave_auth_context.FindEnclaveIdentity(identity_description);
  if (!identity_result.ok()) {
    LOG(ERROR) << "FindEnclaveIdentity failed: " << identity_result.status();
    return Status(error::GoogleError::PERMISSION_DENIED,
                  absl::StrCat("Peer does not have identity ",
                               identity_description.ShortDebugString()));
  }

  const EnclaveIdentity *identity = identity_result.ValueOrDie();
  StatusOr<bool> match_result =
      identity_expectation_matcher.Match(*identity, identity_expectation);
  if (!match_result.ok()) {
    LOG(ERROR) << "Matching identity and expectation failed: "
               << match_result.status();
    return Status(error::GoogleError::INTERNAL,
                  "Error while attempting to compare identity and expectation");
  }
  return match_result.ValueOrDie();
}

}  // namespace asylo
