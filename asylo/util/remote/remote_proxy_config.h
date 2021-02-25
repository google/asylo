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

#ifndef ASYLO_UTIL_REMOTE_REMOTE_PROXY_CONFIG_H_
#define ASYLO_UTIL_REMOTE_REMOTE_PROXY_CONFIG_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "asylo/platform/primitives/remote/metrics/clients/opencensus_client_config.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

namespace asylo {

// RemoteProxyConnectionConfig holds credentials and channel configuration for
// establishing the gRPC connection between a RemoteProxy server and client.
class RemoteProxyConnectionConfig {
 public:
  static StatusOr<std::unique_ptr<RemoteProxyConnectionConfig>> Defaults();

  // Factory method for creating a RemoteProxyConnectionConfig.
  static std::unique_ptr<RemoteProxyConnectionConfig> Create(
      const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
      const ::grpc::ChannelArguments &channel_args,
      const std::shared_ptr<::grpc::ServerCredentials> &server_creds);

  RemoteProxyConnectionConfig(const RemoteProxyConnectionConfig &other) =
      delete;
  RemoteProxyConnectionConfig &operator=(
      const RemoteProxyConnectionConfig &other) = delete;

  std::shared_ptr<::grpc::ChannelCredentials> channel_creds() const {
    return channel_creds_;
  }
  ::grpc::ChannelArguments channel_args() const { return channel_args_; }
  std::shared_ptr<::grpc::ServerCredentials> server_creds() const {
    return server_creds_;
  }

 private:
  RemoteProxyConnectionConfig(
      const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
      const ::grpc::ChannelArguments &channel_args,
      const std::shared_ptr<::grpc::ServerCredentials> &server_creds)
      : channel_creds_(channel_creds),
        channel_args_(channel_args),
        server_creds_(server_creds) {}

  const std::shared_ptr<::grpc::ChannelCredentials> channel_creds_;
  const ::grpc::ChannelArguments channel_args_;
  const std::shared_ptr<::grpc::ServerCredentials> server_creds_;
};

class RemoteProxyConfig {
 public:
  RemoteProxyConfig(
      std::unique_ptr<RemoteProxyConnectionConfig> connection_config)
      : connection_config_(std::move(connection_config)) {}

  RemoteProxyConfig(const RemoteProxyConfig &other) = delete;
  RemoteProxyConfig &operator=(const RemoteProxyConfig &other) = delete;

  virtual ~RemoteProxyConfig() = default;

  std::shared_ptr<::grpc::ChannelCredentials> channel_creds() const {
    return connection_config_->channel_creds();
  }
  ::grpc::ChannelArguments channel_args() const {
    return connection_config_->channel_args();
  }
  std::shared_ptr<::grpc::ServerCredentials> server_creds() const {
    return connection_config_->server_creds();
  }

 private:
  std::unique_ptr<RemoteProxyConnectionConfig> connection_config_;
};

// |RemoteProxyClientConfig| provides |RemoteEnclaveProxyClient| with the
// configuration needed to make a secure connection with a
// |RemoteEnclaveProxyServer|.
//
// |DefaultsWithProvision| should cover most use cases where the
// |GrpcChannelBuilder| and |GrpcCredentialBuilder| are being utilized and
// proxy provisioning is delegate to |RemoteProvision| object.
//
// |Create| allows the user to provide their own credentialing method and
// channel arguments.
//
// |Create| Example Usage:
//   // Build an |SgxLoader| that will be wrapped in a |RemoteEnclaveLoader|.
//   SgxLoader sgx_loader("/path/to/the/enclave.so", /*debug=*/false);
//
//   // Build a |RemoteProxyClientConfig| for use by a |RemoteEnclaveLoader| to
//   // pass config values when it creates the |RemoteEnclaveProxyClient|.
//   const char enclave_name[] = "example enclave";
//   auto remote_proxy_config = RemoteProxyClientConfig::Create(
//       /*channel_creds=*/::grpc::InsecureChannelCredentials(),
//       /*channel_args=*/GrcpChannelBuilder::BuildChannelArguments(),
//       /*server_creds=*/::grpc::InsecureServerCredentials(),
//       /*provision=*/RemoteProvision::Instantiate())
//
//   // Build a |RemoteEnclaveLoader| for use by a |EnclaveManager|.
//   // RemoteEnclaveLoader remote_loader(sgx_loader, remote_proxy_config);
//
// |channel_creds| are the creds required to connect to the
// |RemoteEnclaveProxyServer|.
// |channel_args| are any additional arguments needed for a gRPC Channel.
// |server_creds| are the creds required for incoming connections to the
// |RemoteEnclaveProxyClient|.
// |provision| is a provisioning object.
class RemoteProxyClientConfig : public RemoteProxyConfig {
 public:
  static StatusOr<std::unique_ptr<RemoteProxyClientConfig>>
  DefaultsWithProvision(std::unique_ptr<RemoteProvision> provision);

  static StatusOr<std::unique_ptr<RemoteProxyClientConfig>> Create(
      const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
      const ::grpc::ChannelArguments &channel_args,
      const std::shared_ptr<::grpc::ServerCredentials> &server_creds,
      std::unique_ptr<RemoteProvision> provision);

  RemoteProxyClientConfig(const RemoteProxyClientConfig &other) = delete;
  RemoteProxyClientConfig &operator=(const RemoteProxyClientConfig &other) =
      delete;

  StatusOr<std::string> RunProvision(int32_t client_port,
                                     absl::string_view enclave_path) {
    return provision_->Provision(client_port, enclave_path);
  }
  void RunFinalize() { provision_->Finalize(); }

  // EnableMetricsCollection allows a user to turn on OpenCensus metrics
  // collection of enclave process metrics.
  // Note: Metrics will be collected, but an exporter needs to be setup per the
  // OpenCensus instructions. An example of exporting to Prometheus is located
  // here: https://opencensus.io/quickstart/cpp/metrics/#exporting-to-prometheus
  void EnableOpenCensusMetricsCollection(absl::Duration granularity,
                                         absl::string_view view_name_root) {
    OpenCensusClientConfig config;
    config.granularity = granularity;
    config.view_name_root = std::string(view_name_root);
    open_census_config_ = config;
  }

  bool HasOpenCensusMetricsConfig() const {
    return open_census_config_.has_value();
  }

  StatusOr<OpenCensusClientConfig> GetOpenCensusMetricsConfig() const {
    if (!HasOpenCensusMetricsConfig()) {
      return absl::FailedPreconditionError("OpenCensusConfig is not set");
    }
    return *open_census_config_;
  }

 private:
  RemoteProxyClientConfig(
      std::unique_ptr<RemoteProxyConnectionConfig> connection_config,
      std::unique_ptr<RemoteProvision> provision)
      : RemoteProxyConfig(std::move(connection_config)),
        provision_(std::move(provision)) {}

  const std::unique_ptr<RemoteProvision> provision_;

  // Configuration for OpenCensus.
  absl::optional<OpenCensusClientConfig> open_census_config_;
};

// |RemoteProxyServerConfig| provides a |RemoteEnclaveProxyServer| with the
// configuration needed to make a secure connection with a
// |RemoteEnclaveProxyClient|.
//
// |DefaultsWithHostAddress| should cover most local use cases where the
// Server and Client are on the same machine and the |GrpcChannelBuilder| and
// |GrpcCredentialBuilder| utility classes are being utilized.
//
// |DefaultsWithAddresses| covers most cases where the Server and Client reside
// on separate machines and the |GrpcChannelBuilder| and |GrpcCredentialBuilder|
// utility classes are being utilized.
//
// |Create| allows the user to provide their own credentials and channel
// arguments.
//
// |channel_creds| are the creds required to connect to the
// |RemoteEnclaveProxyClient|.
// |channel_args| are any additional arguments needed for a gRPC Channel.
// |server_creds| are the creds required for incoming connections to the
// |RemoteEnclaveProxyServer|.
// |host_address| is the address and port of the |RemoteEnclaveProxyClient|
// should be in IPv6, for example: '[1234:abcd:5678:f12::ab]:1234'
// |local_address| is the IPv6 address of the desired network interface with no
// port. (Port will be assigned automatically and sent to the Client.)
class RemoteProxyServerConfig : public RemoteProxyConfig {
 public:
  static StatusOr<std::unique_ptr<RemoteProxyServerConfig>>
  DefaultsWithHostAddress(absl::string_view host_address);

  static StatusOr<std::unique_ptr<RemoteProxyServerConfig>>
  DefaultsWithAddresses(absl::string_view host_address,
                        absl::string_view local_address);

  // |channel_creds|, |channel_args|, and |server_creds| will be copied into a
  // |RemoteProxyConnectionConfig|.
  static StatusOr<std::unique_ptr<RemoteProxyServerConfig>> Create(
      const std::shared_ptr<::grpc::ChannelCredentials> &channel_creds,
      const ::grpc::ChannelArguments &channel_args,
      const std::shared_ptr<::grpc::ServerCredentials> &server_creds,
      absl::string_view host_address, absl::string_view local_address);

  RemoteProxyServerConfig(const RemoteProxyServerConfig &other) = delete;
  RemoteProxyServerConfig &operator=(const RemoteProxyServerConfig &other) =
      delete;

  const std::string host_address() const { return host_address_; }
  const std::string local_address() const { return local_address_; }

 private:
  RemoteProxyServerConfig(
      std::unique_ptr<RemoteProxyConnectionConfig> connection_config,
      absl::string_view host_address, absl::string_view local_address)
      : RemoteProxyConfig(std::move(connection_config)),
        host_address_(host_address),
        local_address_(local_address) {}

  const std::string host_address_;
  const std::string local_address_;
};

}  //  namespace asylo

#endif  // ASYLO_UTIL_REMOTE_REMOTE_PROXY_CONFIG_H_
