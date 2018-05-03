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

#include "asylo/daemon/identity/attestation_domain_client.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/daemon/identity/attestation_domain_mock.grpc.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"
#include "test/core/util/port.h"
#include "util/time/clock.h"

namespace asylo {
namespace daemon {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;

constexpr char kAttestationDomain[] = "A 16-byte string";

// Verifies that the client returns the attestation domain provided by the
// server.
TEST(AttestationDomainClientMockTest, GeAttestationDomain) {
  auto mock_stub =
      absl::make_unique<MockAttestationDomainServiceStub>();

  GetAttestationDomainResponse response;
  response.set_attestation_domain(kAttestationDomain);

  EXPECT_CALL(*mock_stub, GetAttestationDomain(_, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(response), Return(grpc::Status::OK)));

  std::unique_ptr<AttestationDomainService::StubInterface> stub =
      std::move(mock_stub);
  AttestationDomainClient client(std::move(stub));

  StatusOr<std::string> domain_result = client.GetAttestationDomain();
  ASSERT_THAT(domain_result, IsOk());
  EXPECT_EQ(domain_result.ValueOrDie(), kAttestationDomain);
}

}  // namespace
}  // namespace daemon
}  // namespace asylo
