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

#include "asylo/util/remote/grpc_channel_builder.h"

#include "absl/flags/flag.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {

StatusOr<std::shared_ptr<::grpc::Channel>> GrpcChannelBuilder::BuildChannel(
    absl::string_view server_address) {
  std::shared_ptr<::grpc::ChannelCredentials> creds;
  ASYLO_ASSIGN_OR_RETURN(
      creds, primitives::GrpcCredentialBuilder::BuildChannelCredentials());
  ::grpc::ChannelArguments args;
  ASYLO_ASSIGN_OR_RETURN(args, BuildChannelArguments());
  return ::grpc::CreateCustomChannel(std::string(server_address), creds, args);
}

StatusOr<::grpc::ChannelArguments> GrpcChannelBuilder::BuildChannelArguments() {
  ::grpc::ChannelArguments channel_args;
  if (absl::GetFlag(FLAGS_security_type) == "ssl") {
    // Substitute actual ssl name.
    channel_args.SetSslTargetNameOverride("common_ssl_name");
  }
  return channel_args;
}

}  // namespace asylo
