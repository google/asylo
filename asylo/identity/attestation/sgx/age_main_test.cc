/*
 *
 * Copyright 2020 Asylo authors
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

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "asylo/test/util/exec_tester.h"
#include "asylo/test/util/status_matchers.h"

ABSL_FLAG(std::string, loader_path, "", "Path to enclave loader");

// Must be passed to the test.
ABSL_FLAG(std::string, age_path, "", "Path to the AGE binary");

// Default to debug AGE for the test.
ABSL_FLAG(bool, is_debuggable_enclave, true,
          "Whether to run the AGE in debug mode");

ABSL_FLAG(bool, age_validate_certificate_chains, false,
          "Whether the AGE should validate its certificate chains");

// Default to a short server lifetime for the test.
ABSL_FLAG(absl::Duration, server_lifetime, absl::Seconds(2),
          "The amount of time to run the AGE's attestation server before "
          "exiting");

namespace asylo {
namespace sgx {
namespace {

class SgxPlatformInfoExecTester : public experimental::ExecTester {
 public:
  SgxPlatformInfoExecTester(const std::vector<std::string> &args)
      : ExecTester(args) {}

 protected:
  bool CheckLine(const std::string &line) override {
    if (line.find("pce_svn") != std::string::npos) {
      pce_svn_found_ = true;
    }
    if (line.find("pce_id") != std::string::npos) {
      pce_id_found_ = true;
    }
    if (line.find("cpu_svn") != std::string::npos) {
      cpu_svn_found_ = true;
    }
    if (line.find("Encrypted PPID") != std::string::npos) {
      encrypted_ppid_found_ = true;
    }
    if (line.find("ppid") != std::string::npos) {
      decrypted_ppid_found_ = true;
    }
    return true;
  }

  bool FinalCheck(bool accumulated) override {
    return pce_svn_found_ && pce_id_found_ && cpu_svn_found_ &&
           (encrypted_ppid_found_ || decrypted_ppid_found_);
  }

 private:
  bool pce_svn_found_ = false;
  bool pce_id_found_ = false;
  bool cpu_svn_found_ = false;
  bool encrypted_ppid_found_ = false;
  bool decrypted_ppid_found_ = false;
};

TEST(AgeMainTest, FakeCertificationSuccess) {
  experimental::ExecTester tester(
      {absl::GetFlag(FLAGS_loader_path), "--start_age", "--use_fake_pce",
       absl::StrCat("--age_validate_certificate_chains=true"),
       absl::StrCat("--server_lifetime=",
                    absl::FormatDuration(absl::GetFlag(FLAGS_server_lifetime))),
       absl::StrCat("--is_debuggable_enclave=",
                    absl::GetFlag(FLAGS_is_debuggable_enclave)),
       absl::StrCat("--age_path=", absl::GetFlag(FLAGS_age_path))});

  int status = -1;

  ASSERT_TRUE(tester.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

}

TEST(AgeMainTest, FakePrintPlatformInfoSuccess) {
  SgxPlatformInfoExecTester tester(
      {absl::GetFlag(FLAGS_loader_path), "--print_sgx_platform_info",
       "--use_fake_pce",
       absl::StrCat("--server_lifetime=",
                    absl::FormatDuration(absl::GetFlag(FLAGS_server_lifetime))),
       absl::StrCat("--is_debuggable_enclave=",
                    absl::GetFlag(FLAGS_is_debuggable_enclave)),
       absl::StrCat("--age_path=", absl::GetFlag(FLAGS_age_path))});

  int status = -1;

  ASSERT_TRUE(tester.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(AgeMainTest, FakePrintPlatformInfoRandomPpidekSuccess) {
  SgxPlatformInfoExecTester tester(
      {absl::GetFlag(FLAGS_loader_path), "--print_sgx_platform_info",
       "--use_fake_pce", "--print_plaintext_ppid",
       absl::StrCat("--server_lifetime=",
                    absl::FormatDuration(absl::GetFlag(FLAGS_server_lifetime))),
       absl::StrCat("--is_debuggable_enclave=",
                    absl::GetFlag(FLAGS_is_debuggable_enclave)),
       absl::StrCat("--age_path=", absl::GetFlag(FLAGS_age_path))});

  int status = -1;

  ASSERT_TRUE(tester.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
