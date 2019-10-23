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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_GRPC_CREDENTIAL_BUILDER_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_GRPC_CREDENTIAL_BUILDER_H_

#include <string>

#include "absl/flags/declare.h"
#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"

ABSL_DECLARE_FLAG(std::string, security_type);
ABSL_DECLARE_FLAG(std::string, ssl_cert);
ABSL_DECLARE_FLAG(std::string, ssl_key);

namespace asylo {
namespace primitives {

class GrpcCredentialBuilder {
 public:
  GrpcCredentialBuilder() = delete;

  static StatusOr<std::shared_ptr<::grpc::ServerCredentials>>
  BuildServerCredentials();

  static StatusOr<std::shared_ptr<::grpc::ChannelCredentials>>
  BuildChannelCredentials();
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_GRPC_CREDENTIAL_BUILDER_H_
