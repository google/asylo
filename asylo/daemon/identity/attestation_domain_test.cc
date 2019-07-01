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

#include "asylo/daemon/identity/attestation_domain.h"

#include <sys/file.h>
#include <unistd.h>

#include <cstdlib>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/escaping.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {

using ::testing::Not;

namespace {

constexpr char kAll0[] = "00000000000000000000000000000000";
constexpr char kAllF[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
constexpr char kAttestationDomainTooShort[] = "FFFF";
constexpr char kAttestationDomainTooLong[] =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
constexpr char kAttestationDomainBadChars[] =
    "FFFFWFFFFFFFFFFFFFFFFFFFFFFFFFFF";
constexpr char kAttestationDomainFileName[] =
    "/asylo-local-attestation-domain-file";

// A test fixture is used for managing the attestation-domain file and its path.
class AttestationDomainTest : public ::testing::Test {
 protected:
  AttestationDomainTest() {
    domain_file_path_ =
        absl::GetFlag(FLAGS_test_tmpdir) + kAttestationDomainFileName;
  }

  ~AttestationDomainTest() override {
    // Remove domain_file_path_.c_str() if it exists.
    unlink(domain_file_path_.c_str());
  }

  std::string domain_file_path_;
};

TEST_F(AttestationDomainTest, AttestationDomainReadAll0) {
  int fd = open(domain_file_path_.c_str(), O_EXCL | O_CREAT | O_RDWR);
  ASSERT_GT(fd, 0);
  ASSERT_EQ(fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO), 0);
  ASSERT_EQ(write(fd, kAll0, sizeof(kAll0) - 1), sizeof(kAll0) - 1);
  EXPECT_EQ(close(fd), 0);

  std::string domain;
  ASSERT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain), IsOk());
  EXPECT_EQ(domain, absl::HexStringToBytes(kAll0));
}

TEST_F(AttestationDomainTest, AttestationDomainReadAllF) {
  int fd = open(domain_file_path_.c_str(), O_EXCL | O_CREAT | O_RDWR);
  ASSERT_GT(fd, 0);
  ASSERT_EQ(fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO), 0);
  ASSERT_EQ(write(fd, kAllF, sizeof(kAllF) - 1), sizeof(kAllF) - 1);
  EXPECT_EQ(close(fd), 0);

  std::string domain;
  ASSERT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain), IsOk());
  EXPECT_EQ(domain, absl::HexStringToBytes(kAllF));
}

TEST_F(AttestationDomainTest, AttestationDomainCreate) {
  std::string domain1;
  ASSERT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain1),
              IsOk());
  ASSERT_EQ(domain1.size(), kAttestationDomainNameSize);

  std::string domain2;
  ASSERT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain2),
              IsOk());
  EXPECT_EQ(domain1, domain2);
}

TEST_F(AttestationDomainTest, AttestationDomainTooShort) {
  int fd = open(domain_file_path_.c_str(), O_EXCL | O_CREAT | O_RDWR);
  ASSERT_GT(fd, 0);
  ASSERT_EQ(fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO), 0);
  ASSERT_EQ(write(fd, kAttestationDomainTooShort,
                  sizeof(kAttestationDomainTooShort) - 1),
            sizeof(kAttestationDomainTooShort) - 1);
  EXPECT_EQ(close(fd), 0);

  std::string domain;
  EXPECT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain),
              Not(IsOk()));
}

TEST_F(AttestationDomainTest, AttestationDomainTooLong) {
  int fd = open(domain_file_path_.c_str(), O_EXCL | O_CREAT | O_RDWR);
  ASSERT_GT(fd, 0);
  ASSERT_EQ(fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO), 0);
  ASSERT_EQ(write(fd, kAttestationDomainTooLong,
                  sizeof(kAttestationDomainTooLong) - 1),
            sizeof(kAttestationDomainTooLong) - 1);
  EXPECT_EQ(close(fd), 0);

  std::string domain;
  EXPECT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain),
              Not(IsOk()));
}

TEST_F(AttestationDomainTest, AttestationDomainBadChars) {
  int fd = open(domain_file_path_.c_str(), O_EXCL | O_CREAT | O_RDWR);
  ASSERT_GT(fd, 0);
  ASSERT_EQ(fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO), 0);
  ASSERT_EQ(write(fd, kAttestationDomainBadChars,
                  sizeof(kAttestationDomainBadChars) - 1),
            sizeof(kAttestationDomainBadChars) - 1);
  EXPECT_EQ(close(fd), 0);

  std::string domain;
  EXPECT_THAT(GetAttestationDomain(domain_file_path_.c_str(), &domain),
              Not(IsOk()));
}

}  // namespace
}  // namespace asylo
