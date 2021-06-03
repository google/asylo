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

#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_impl.h"

#include <memory>
#include <vector>

#include "absl/status/status.h"
#include "asylo/grpc/auth/enclave_auth_context.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace {

Status ExtractSgxIdentity(const EnclaveAuthContext &auth_context,
                          SgxIdentity *sgx_identity) {
  EnclaveIdentityDescription enclave_identity_description;
  SetSgxIdentityDescription(&enclave_identity_description);
  StatusOr<const EnclaveIdentity *> identity_result =
      auth_context.FindEnclaveIdentity(enclave_identity_description);
  if (!identity_result.ok()) {
    LOG(ERROR) << "FindEnclaveIdentity failed: " << identity_result.status();
    return Status(absl::StatusCode::kPermissionDenied,
                  "Peer does not have SGX identity");
  }

  ASYLO_ASSIGN_OR_RETURN(*sgx_identity,
                         ParseSgxIdentity(*identity_result.value()));
  return absl::OkStatus();
}

}  // namespace

SgxRemoteAssertionGeneratorImpl::SgxRemoteAssertionGeneratorImpl()
    : signing_key_(nullptr),
      certificate_chains_(std::vector<CertificateChain>()) {}

SgxRemoteAssertionGeneratorImpl::SgxRemoteAssertionGeneratorImpl(
    std::unique_ptr<SigningKey> signing_key,
    const std::vector<CertificateChain> &certificate_chains)
    : signing_key_(std::move(signing_key)),
      certificate_chains_(certificate_chains) {}

::grpc::Status SgxRemoteAssertionGeneratorImpl::GenerateSgxRemoteAssertion(
    ::grpc::ServerContext *context,
    const GenerateSgxRemoteAssertionRequest *request,
    GenerateSgxRemoteAssertionResponse *response) {
  StatusOr<EnclaveAuthContext> auth_context_result =
      EnclaveAuthContext::CreateFromAuthContext(*context->auth_context());
  if (!auth_context_result.ok()) {
    LOG(ERROR) << "CreateFromServerContext failed: "
               << auth_context_result.status();
    return ::grpc::Status(
        ::grpc::StatusCode::INTERNAL,
        "Failed to retrieve enclave authentication information");
  }
  EnclaveAuthContext auth_context = auth_context_result.value();

  SgxIdentity sgx_identity;
  Status status = ExtractSgxIdentity(auth_context, &sgx_identity);
  if (!status.ok()) {
    return ConvertStatus<::grpc::Status>(status);
  }
  auto signing_key_locked = signing_key_.ReaderLock();

  if (*signing_key_locked == nullptr) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "No attestation key available");
  }

  auto certificate_chains_locked = certificate_chains_.ReaderLock();
  status = MakeRemoteAssertion(request->user_data(), sgx_identity,
                               **signing_key_locked, *certificate_chains_locked,
                               response->mutable_assertion());
  if (!status.ok()) {
    LOG(ERROR) << "MakeRemoteAssertion failed: " << status;
    return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                          "Failed to generate SGX remote assertion");
  }
  return ::grpc::Status::OK;
}

void SgxRemoteAssertionGeneratorImpl::UpdateSigningKeyAndCertificateChains(
    std::unique_ptr<SigningKey> signing_key,
    const std::vector<CertificateChain> &certificate_chains) {
  auto signing_key_locked = signing_key_.Lock();
  auto certificate_chains_locked = certificate_chains_.Lock();
  *signing_key_locked = std::move(signing_key);
  *certificate_chains_locked = certificate_chains;
}

}  // namespace asylo
