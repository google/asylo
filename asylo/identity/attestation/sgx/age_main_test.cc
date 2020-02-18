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

#include <libgen.h>

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "asylo/test/util/exec_tester.h"
#include "asylo/test/util/status_matchers.h"

ABSL_FLAG(std::string, loader_path, "", "Path to enclave loader");

// Must be passed to the test.
ABSL_FLAG(std::string, age_path, "", "Path to the AGE binary");

// Default to debug AGE for the test.
ABSL_FLAG(bool, is_debuggable_enclave, true,
          "Whether to run the AGE in debug mode");

// Default to a short server lifetime for the test.
ABSL_FLAG(absl::Duration, server_lifetime, absl::Seconds(2),
          "The amount of time to run the AGE's attestation server before "
          "exiting");

namespace asylo {
namespace sgx {
namespace {

TEST(AgeMainTest, FakeCertificationSuccess) {
  experimental::ExecTester tester(
      {absl::GetFlag(FLAGS_loader_path), "--start_age", "--use_fake_pki",
       absl::StrCat("--server_lifetime=",
                    absl::FormatDuration(absl::GetFlag(FLAGS_server_lifetime))),
       absl::StrCat("--is_debuggable_enclave=",
                    absl::GetFlag(FLAGS_is_debuggable_enclave)),
       absl::StrCat("--age_path=", absl::GetFlag(FLAGS_age_path))});

  int status = -1;

  ASSERT_TRUE(tester.Run("", &status));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));

}

}  // namespace
}  // namespace sgx
}  // namespace asylo
