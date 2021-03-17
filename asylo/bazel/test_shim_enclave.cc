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
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "asylo/bazel/test_shim_enclave.pb.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/test/util/test_flags.h"
#include <benchmark/benchmark.h>

namespace asylo {

// A TrustedApplication that runs a gtest test suite. Fails if tests fail.
class TestShimEnclave : public EnclaveTestCase {
 public:
  TestShimEnclave() = default;

  Status Initialize(const EnclaveConfig &config) override {
    // Let the test framework know where to write the results summary.
    TestShimEnclaveConfig shim_config =
        config.GetExtension(test_shim_enclave_config);

    if (shim_config.has_output_file()) {
      ::testing::GTEST_FLAG(output) = shim_config.output_file().c_str();
    }

    if (shim_config.has_test_tmpdir()) {
      absl::SetFlag(&FLAGS_test_tmpdir, shim_config.test_tmpdir());
    }

    if (shim_config.has_benchmarks()) {
      benchmark_flag = shim_config.benchmarks();
    }

    if (shim_config.has_test_in_initialize() &&
        shim_config.test_in_initialize()) {
      test_in_initialize_ = true;
      EnclaveRunAllTests();
    } else {
      test_in_initialize_ = false;
    }

    return absl::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    if (!test_in_initialize_) {
      EnclaveRunAllTests();
    }
    return absl::OkStatus();
  }

 private:
  void EnclaveRunAllTests() {
    int argc = 1;
    char argv0[] = "benchmarks";
    char *argv[] = {argv0, const_cast<char*>(benchmark_flag.c_str())};
    ::testing::InitGoogleTest(&argc, argv);
    if (!benchmark_flag.empty()) {
      benchmark::RunSpecifiedBenchmarks();
    }
    CHECK_EQ(RUN_ALL_TESTS(), 0);
  }

  bool test_in_initialize_;
  std::string benchmark_flag;
};

TrustedApplication *BuildTrustedApplication() { return new TestShimEnclave; }

}  // namespace asylo
