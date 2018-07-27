/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/daemon/identity/attestation_domain_service_impl.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/daemon/identity/attestation_domain.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "include/grpcpp/server_context.h"

namespace asylo {
namespace daemon {
namespace {

constexpr char kAttestationDomainFileName[] =
    "asylo-local-attestation-domain-file";

// Verifies that the attestation domain name returned by
// AttestationDomainServiceImpl is well-formed and consistent.
TEST(AttestationDomainServiceImplTest, GetAttestationDomain) {
  std::string domain_file_path =
      absl::StrCat(FLAGS_test_tmpdir, "/", kAttestationDomainFileName);
  AttestationDomainServiceImpl impl(domain_file_path);

  GetAttestationDomainRequest request;
  GetAttestationDomainResponse response;
  ::grpc::ServerContext *server_context = nullptr;
  ASSERT_THAT(
      Status(impl.GetAttestationDomain(server_context, &request, &response)),
      IsOk());

  std::string domain1 = response.attestation_domain();
  EXPECT_EQ(domain1.size(), kAttestationDomainNameSize);

  response.Clear();
  ASSERT_THAT(
      Status(impl.GetAttestationDomain(server_context, &request, &response)),
      IsOk());

  std::string domain2 = response.attestation_domain();
  EXPECT_EQ(domain1, domain2);
}

}  // namespace
}  // namespace daemon
}  // namespace asylo
