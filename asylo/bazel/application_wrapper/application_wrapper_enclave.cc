/*
 *
 * Copyright 2018 Asylo authors
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

#include <atomic>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/bazel/application_wrapper/application_wrapper.pb.h"
#include "asylo/bazel/application_wrapper/argv.h"
#include "asylo/util/logging.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

extern int main(int argc, char *argv[]);

namespace asylo {

// An enclave that runs another application, specifically one represented by
// main().
class ApplicationWrapperEnclave final : public TrustedApplication {
 public:
  ApplicationWrapperEnclave() : has_run_(false) {}

  // Initialize() extracts the command-line arguments provided in the
  // command_line_args extension of |config|. Returns an error if |config| does
  // not have a command_line_args extension.
  Status Initialize(const EnclaveConfig &config) override {
    if (!config.HasExtension(command_line_args)) {
      return Status(absl::StatusCode::kInvalidArgument,
                    "Expected command_line_args extension on EnclaveConfig");
    }
    args_unmarshaler_ =
        Argv(config.GetExtension(command_line_args).arguments());

    return absl::OkStatus();
  }

  // Run() executes the application with the command-line arguments from the
  // EnclaveConfig and places the return value from main() in the
  // main_return_value extension of |output|.
  //
  // It is an error to call Run() more than once.
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    // Do not allow the application to run more than once.
    if (has_run_.exchange(true)) {
      return Status(absl::StatusCode::kFailedPrecondition,
                    "Application has already run");
    }

    // Unmarshal the command-line arguments from the EnclaveConfig.
    int argc = args_unmarshaler_.argc();
    char **argv = args_unmarshaler_.argv();

    // Run the application and store its return value in the EnclaveOutput.
    output->SetExtension(main_return_value, main(argc, argv));

    return absl::OkStatus();
  }

  // Finalize() logs a warning if the application has not run.
  Status Finalize(const EnclaveFinal &final_input) override {
    const char *debug_application_name = args_unmarshaler_.argc() > 0
                                             ? args_unmarshaler_.argv()[0]
                                             : "<unknown application>";

    LOG_IF(WARNING, !has_run_.load())
        << absl::StrCat(debug_application_name,
                        " enclave finalizing before application has run");

    return absl::OkStatus();
  }

 private:
  // Indicates whether the application has already run or is running.
  std::atomic_bool has_run_;

  // The command-line arguments to pass to the application.
  Argv args_unmarshaler_;
};

TrustedApplication *BuildTrustedApplication() {
  return new ApplicationWrapperEnclave;
}

}  // namespace asylo
