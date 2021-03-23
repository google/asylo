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

#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"

ABSL_FLAG(std::string, security_type, "local",
          "Type of Security desired, one of:\n"
          "ssl: ssl_key and ssl_cert are required for server credentials.\n"
          "local: Will use local security credentials.");
ABSL_FLAG(std::string, ssl_key, "", "Path to the ssl_key.");
ABSL_FLAG(std::string, ssl_cert, "", "Path to the ssl_cert.");

namespace asylo {
namespace primitives {

namespace {

enum SecurityType {
  kSSL,
  kLocal,
};

StatusOr<SecurityType> ParseFlag(absl::string_view text) {
  const std::string text_lower = absl::AsciiStrToLower(text);
  if (text_lower == "ssl") {
    return SecurityType::kSSL;
  }
  if (text_lower == "local") {
    return SecurityType::kLocal;
  }
  LOG(ERROR) << "Invalid security_type specified, '" << text << "'";
  return absl::InvalidArgumentError(
      absl::StrCat("Invalid security_type was specified, '", text, "'"));
}

absl::string_view UnparseFlag(SecurityType in) {
  static constexpr absl::string_view kSsl = "ssl";
  static constexpr absl::string_view kLocal = "local";
  static constexpr absl::string_view kUnknown = "unknown";
  switch (in) {
    case SecurityType::kSSL:
      return kSsl;
    case SecurityType::kLocal:
      return kLocal;
    default:
      return kUnknown;
  }
}

StatusOr<std::string> ReadFile(absl::string_view path) {
  int fd = open(std::string(path).c_str(), O_RDONLY);
  if (fd == -1) {
    return LastPosixError(absl::StrCat("Failed to open, file=", path));
  }
  Cleanup close_fd([fd]() { close(fd); });

  struct stat statbuf;
  if (fstat(fd, &statbuf) < 0) {
    return LastPosixError(absl::StrCat("Failed to stat, file=", path));
  }
  auto buf = absl::make_unique<char[]>(statbuf.st_size);
  const auto read_result = read(fd, buf.get(), statbuf.st_size);
  if (read_result == -1) {
    return LastPosixError(absl::StrCat("Failed to read, file=", path));
  }
  if (read_result < statbuf.st_size) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Could not read ", statbuf.st_size, " bytes, file=", path));
  }
  return std::string(buf.get(), statbuf.st_size);
}

}  // namespace

StatusOr<std::shared_ptr<::grpc::ServerCredentials>>
GrpcCredentialBuilder::BuildServerCredentials() {
  SecurityType security_type;
  ASYLO_ASSIGN_OR_RETURN(security_type,
                         ParseFlag(absl::GetFlag(FLAGS_security_type)));
  VLOG(1) << "Building Server Credentials for security_type="
          << UnparseFlag(security_type);
  switch (security_type) {
    case SecurityType::kSSL: {
      std::string ssl_key;
      ASYLO_ASSIGN_OR_RETURN(ssl_key, ReadFile(absl::GetFlag(FLAGS_ssl_key)));
      std::string ssl_cert;
      ASYLO_ASSIGN_OR_RETURN(ssl_cert, ReadFile(absl::GetFlag(FLAGS_ssl_cert)));
      ::grpc::SslServerCredentialsOptions::PemKeyCertPair cert_pair = {
          ssl_key, ssl_cert};
      ::grpc::SslServerCredentialsOptions ssl_cred_options;
      ssl_cred_options.pem_key_cert_pairs.emplace_back(cert_pair);
      return ::grpc::SslServerCredentials(ssl_cred_options);
    }
    case SecurityType::kLocal:
      return ::grpc::InsecureServerCredentials();
    default:
      LOG(ERROR) << "Invalid security_type specified, " << security_type;
      return absl::InvalidArgumentError("Invalid security_type was specified.");
  }
}

StatusOr<std::shared_ptr<::grpc::ChannelCredentials>>
GrpcCredentialBuilder::BuildChannelCredentials() {
  SecurityType security_type;
  ASYLO_ASSIGN_OR_RETURN(security_type,
                         ParseFlag(absl::GetFlag(FLAGS_security_type)));
  VLOG(1) << "Building Channel Credentials for security_type="
          << UnparseFlag(security_type);
  switch (security_type) {
    case SecurityType::kSSL: {
      ::grpc::SslCredentialsOptions ssl_cred_ops;
      ASYLO_ASSIGN_OR_RETURN(ssl_cred_ops.pem_root_certs,
                             ReadFile(absl::GetFlag(FLAGS_ssl_cert)));
      return ::grpc::SslCredentials(ssl_cred_ops);
    }
    case SecurityType::kLocal:
      return ::grpc::InsecureChannelCredentials();
    default:
      return absl::InvalidArgumentError("Invalid security_type was specified.");
  }
}

}  // namespace primitives
}  // namespace asylo
