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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_errors.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"

using ::testing::Ne;
using ::testing::Not;

namespace asylo {
namespace primitives {
namespace {

Status WriteFile(absl::string_view path, absl::string_view data) {
  int fd = open(std::string(path).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd == -1) {
    return LastPosixError(absl::StrCat("Failed to open, file=", path));
  }
  Cleanup close_fd([fd]() { close(fd); });

  const auto write_result = write(fd, data.data(), data.size());
  if (write_result == -1) {
    return LastPosixError(absl::StrCat("Failed to write, file=", path));
  }
  if (write_result < data.size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Could not write ", data.size(), " bytes, file=", path));
  }
  return absl::OkStatus();
}

TEST(GrpcCredentialBuilderTest, GeneratesServerSSLCredentials) {
  const std::string temp_cert_filename = absl::StrCat(
      absl::GetFlag(FLAGS_test_tmpdir), "/GeneratesSSLCredentials_cert");
  ASYLO_ASSERT_OK(WriteFile(temp_cert_filename, "Totally a Cert"));
  absl::SetFlag(&FLAGS_ssl_cert, temp_cert_filename);

  const std::string temp_key_filename = absl::StrCat(
      absl::GetFlag(FLAGS_test_tmpdir), "/GeneratesSSLCredentials_key");
  ASYLO_ASSERT_OK(WriteFile(temp_key_filename, "Totally a Key"));
  absl::SetFlag(&FLAGS_ssl_key, temp_key_filename);

  absl::SetFlag(&FLAGS_security_type, "ssl");
  std::shared_ptr<::grpc::ServerCredentials> ssl_creds;
  ASYLO_ASSERT_OK_AND_ASSIGN(ssl_creds,
                             GrpcCredentialBuilder::BuildServerCredentials());
  EXPECT_THAT(ssl_creds, Ne(nullptr));
}

TEST(GrpcCredentialBuilderTest, GeneratesServerLocalCredentials) {
  absl::SetFlag(&FLAGS_security_type, "local");

  std::shared_ptr<::grpc::ServerCredentials> ssl_creds;
  ASYLO_ASSERT_OK_AND_ASSIGN(ssl_creds,
                             GrpcCredentialBuilder::BuildServerCredentials());
  EXPECT_THAT(ssl_creds, Ne(nullptr));
}

TEST(GrpcCredentialBuilderTest, GeneratesChannelSSLCredentials) {
  const std::string temp_cert_filename = absl::StrCat(
      absl::GetFlag(FLAGS_test_tmpdir), "/GeneratesChannelSSLCredentials_cert");
  ASYLO_ASSERT_OK(WriteFile(temp_cert_filename, "Totally a Cert"));
  absl::SetFlag(&FLAGS_ssl_cert, temp_cert_filename);

  absl::SetFlag(&FLAGS_security_type, "ssl");
  std::shared_ptr<::grpc::ChannelCredentials> ssl_creds;
  ASYLO_ASSERT_OK_AND_ASSIGN(ssl_creds,
                             GrpcCredentialBuilder::BuildChannelCredentials());
  EXPECT_THAT(ssl_creds, Ne(nullptr));
}

TEST(GrpcCredentialBuilderTest, GeneratesChannelLocalCredentials) {
  absl::SetFlag(&FLAGS_security_type, "local");

  std::shared_ptr<::grpc::ChannelCredentials> ssl_creds;
  ASYLO_ASSERT_OK_AND_ASSIGN(ssl_creds,
                             GrpcCredentialBuilder::BuildChannelCredentials());
  EXPECT_THAT(ssl_creds, Ne(nullptr));
}

TEST(GrpcCredentialBuilderTest, RejectsArbitrarySecurityTypes) {
  absl::SetFlag(&FLAGS_security_type, "IceCream");
  ASSERT_THAT(GrpcCredentialBuilder::BuildServerCredentials(), Not(IsOk()));

  absl::SetFlag(&FLAGS_security_type, "Doritos");
  ASSERT_THAT(GrpcCredentialBuilder::BuildChannelCredentials(), Not(IsOk()));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
