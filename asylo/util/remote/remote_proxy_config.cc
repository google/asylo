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

#include "asylo/util/remote/remote_proxy_config.h"

#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"
#include "asylo/util/remote/grpc_channel_builder.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {

namespace {

struct DefaultGrpcConfig {
  std::shared_ptr<::grpc::ChannelCredentials> channel_creds;
  std::shared_ptr<::grpc::ServerCredentials> server_creds;
  ::grpc::ChannelArguments channel_args;
};

StatusOr<DefaultGrpcConfig> GetDefaultGrpcConfig() {
  DefaultGrpcConfig default_config;
  ASYLO_ASSIGN_OR_RETURN(
      default_config.channel_creds,
      primitives::GrpcCredentialBuilder::BuildChannelCredentials());
  ASYLO_ASSIGN_OR_RETURN(default_config.channel_args,
                         GrpcChannelBuilder::BuildChannelArguments());
  ASYLO_ASSIGN_OR_RETURN(
      default_config.server_creds,
      primitives::GrpcCredentialBuilder::BuildServerCredentials());
  return default_config;
}

}  //  namespace

StatusOr<std::unique_ptr<RemoteProxyConnectionConfig>>
RemoteProxyConnectionConfig::Defaults() {
  DefaultGrpcConfig default_config;
  ASYLO_ASSIGN_OR_RETURN(default_config, GetDefaultGrpcConfig());

  return Create(default_config.channel_creds, default_config.channel_args,
                default_config.server_creds);
}

std::unique_ptr<RemoteProxyConnectionConfig>
RemoteProxyConnectionConfig::Create(
    const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
    const ::grpc::ChannelArguments &channel_args,
    const std::shared_ptr<::grpc::ServerCredentials> &server_creds) {
  return absl::WrapUnique<RemoteProxyConnectionConfig>(
      new RemoteProxyConnectionConfig(channel_creds, channel_args,
                                      server_creds));
}

StatusOr<std::unique_ptr<RemoteProxyClientConfig>>
RemoteProxyClientConfig::DefaultsWithProvision(
    std::unique_ptr<RemoteProvision> provision) {
  DefaultGrpcConfig default_config;
  ASYLO_ASSIGN_OR_RETURN(default_config, GetDefaultGrpcConfig());

  return RemoteProxyClientConfig::Create(
      default_config.channel_creds, default_config.channel_args,
      default_config.server_creds, std::move(provision));
}

StatusOr<std::unique_ptr<RemoteProxyClientConfig>>
RemoteProxyClientConfig::Create(
    const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
    const ::grpc::ChannelArguments &channel_args,
    const std::shared_ptr<::grpc::ServerCredentials> &server_creds,
    std::unique_ptr<RemoteProvision> provision) {
  std::unique_ptr<RemoteProxyConnectionConfig> connection_config =
      RemoteProxyConnectionConfig::Create(channel_creds, channel_args,
                                          server_creds);
  return absl::WrapUnique<RemoteProxyClientConfig>(new RemoteProxyClientConfig(
      std::move(connection_config), std::move(provision)));
}

StatusOr<std::unique_ptr<RemoteProxyServerConfig>>
RemoteProxyServerConfig::DefaultsWithHostAddress(
    absl::string_view host_address) {
  return RemoteProxyServerConfig::DefaultsWithAddresses(host_address, "[::]");
}

StatusOr<std::unique_ptr<RemoteProxyServerConfig>>
RemoteProxyServerConfig::DefaultsWithAddresses(
    absl::string_view host_address, absl::string_view local_address) {
  DefaultGrpcConfig default_config;
  ASYLO_ASSIGN_OR_RETURN(default_config, GetDefaultGrpcConfig());

  return RemoteProxyServerConfig::Create(
      default_config.channel_creds, default_config.channel_args,
      default_config.server_creds, host_address, local_address);
}

StatusOr<std::unique_ptr<RemoteProxyServerConfig>>
RemoteProxyServerConfig::Create(
    const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
    const ::grpc::ChannelArguments &channel_args,
    const std::shared_ptr<::grpc::ServerCredentials> &server_creds,
    absl::string_view host_address, absl::string_view local_address) {
  std::unique_ptr<RemoteProxyConnectionConfig> connection_config =
      RemoteProxyConnectionConfig::Create(channel_creds, channel_args,
                                          server_creds);
  return absl::WrapUnique<RemoteProxyServerConfig>(new RemoteProxyServerConfig(
      std::move(connection_config), host_address, local_address));
}

}  //  namespace asylo
