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

#include <string>

#include <gtest/gtest.h>
#include "asylo/bazel/enclave_test_shim.pb.h"
#include "gflags/gflags.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {

// A TrustedApplication that runs a gtest test suite. Fails if tests fail.
class EnclaveTestShim : public EnclaveTestCase {
 public:
  EnclaveTestShim() = default;

  Status Initialize(const EnclaveConfig &config) override {
    // Let the test framework know where to write the results summary.
    EnclaveTestShimConfig shim_config =
        config.GetExtension(enclave_test_shim_config);
    if (shim_config.has_output_file()) {
      ::testing::GTEST_FLAG(output) = shim_config.output_file().c_str();
    }
    if (shim_config.has_test_tmpdir()) {
      FLAGS_test_tmpdir = shim_config.test_tmpdir();
    }

    return Status::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    int argc = 1;
    char argv0[] = "placeholder";
    char *argv[] = {argv0, nullptr};
    ::testing::InitGoogleTest(&argc, argv);
    CHECK_EQ(RUN_ALL_TESTS(), 0);
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveTestShim; }

}  // namespace asylo
