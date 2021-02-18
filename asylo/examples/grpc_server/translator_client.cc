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

#include "asylo/examples/grpc_server/translator_client.h"

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "asylo/examples/grpc_server/translator_server.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpc/impl/codegen/gpr_types.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"

namespace examples {
namespace grpc_server {
namespace {

const absl::Duration kChannelDeadline = absl::Seconds(5);

// Makes a GetTranslation RPC with |request| to the server backed by *|stub|.
asylo::StatusOr<GetTranslationResponse> GetTranslation(
    const GetTranslationRequest &request, Translator::Stub *stub) {
  GetTranslationResponse response;

  ::grpc::ClientContext context;
  ASYLO_RETURN_IF_ERROR(asylo::ConvertStatus<asylo::Status>(
      stub->GetTranslation(&context, request, &response)));
  return response;
}

}  // namespace

asylo::StatusOr<std::unique_ptr<TranslatorClient>> TranslatorClient::Create(
    absl::string_view address) {
  if (address.empty()) {
    return asylo::Status(absl::StatusCode::kInvalidArgument,
                         "Must provide a non-empty server address");
  }
  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
  ::grpc::InsecureChannelCredentials();

  // Connect a gRPC channel to the server.
  std::shared_ptr<::grpc::Channel> channel =
      ::grpc::CreateChannel(std::string(address), channel_credentials);

  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME),
      gpr_time_from_micros(absl::ToInt64Microseconds(kChannelDeadline),
                           GPR_TIMESPAN));
  if (!channel->WaitForConnected(absolute_deadline)) {
    return asylo::Status(absl::StatusCode::kInternal,
                         "Failed to connect to server");
  }

  return absl::WrapUnique(new TranslatorClient(Translator::NewStub(channel)));
}

asylo::StatusOr<std::string> TranslatorClient::GrpcGetTranslation(
    absl::string_view word_to_translate) {
  if (word_to_translate.empty()) {
    return asylo::Status(absl::StatusCode::kInvalidArgument,
                         "Must provide a non-empty RPC input");
  }

  GetTranslationRequest request;
  request.set_input_word(std::string(word_to_translate));
  GetTranslationResponse response;
  ASYLO_ASSIGN_OR_RETURN(response, GetTranslation(request, stub_.get()));

  return response.translated_word();
}

}  // namespace grpc_server
}  // namespace examples
