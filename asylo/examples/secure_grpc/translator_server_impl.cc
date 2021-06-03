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

#include "asylo/examples/secure_grpc/translator_server_impl.h"

#include <iostream>

#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "asylo/grpc/auth/enclave_auth_context.h"
#include "include/grpcpp/grpcpp.h"

namespace examples {
namespace secure_grpc {

TranslatorServerImpl::TranslatorServerImpl(asylo::IdentityAclPredicate acl)
    : Service(),
      // Initialize the translation map with a few known translations.
      translation_map_({{"asylo", "sanctuary"},
                        {"istio", "sail"},
                        {"kubernetes", "helmsman"}}),
      acl_(std::move(acl)) {}

::grpc::Status TranslatorServerImpl::GetTranslation(
    ::grpc::ServerContext *context,
    const grpc_server::GetTranslationRequest *request,
    grpc_server::GetTranslationResponse *response) {
  // First, access the authentication properties of the connection through
  // EnclaveAuthContext.
  auto auth_context_result = asylo::EnclaveAuthContext::CreateFromAuthContext(
      *context->auth_context());
  if (!auth_context_result.ok()) {
    LOG(ERROR) << "Failed to access authentication context: "
               << auth_context_result.status();
    return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                          "Failed to access authentication context");
  }

  asylo::EnclaveAuthContext auth_context = auth_context_result.value();

  // Now, check whether the peer is authorized to call this RPC.
  std::string explanation;
  auto authorized_result = auth_context.EvaluateAcl(acl_, &explanation);
  if (!authorized_result.ok()) {
    LOG(INFO) << authorized_result.status();
    return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                          "Error occurred while evaluating ACL");
  }

  if (!authorized_result.value()) {
    std::string combined_error =
        absl::StrCat("Peer is unauthorized for GetTranslation: ", explanation);
    std::cout << combined_error << std::endl;
    return ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED,
                          combined_error);
  }

  std::cout << "The peer is authorized for GetTranslation" << std::endl;

  // Confirm that |*request| has an |input_word| field.
  if (!request->has_input_word()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "No input word given");
  }

  // Confirm that the translation map has a translation for the input word.
  auto response_iterator =
      translation_map_.find(absl::AsciiStrToLower(request->input_word()));
  if (response_iterator == translation_map_.end()) {
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          absl::StrCat("No known translation for \"",
                                       request->input_word(), "\""));
  }

  // Return the translation.
  response->set_translated_word(response_iterator->second);
  return ::grpc::Status::OK;
}

}  // namespace secure_grpc
}  // namespace examples
