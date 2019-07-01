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

#include <fcntl.h>
#include <libgen.h>

#include <cstdlib>
#include <functional>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/test_flags.h"

using testing::HasSubstr;
using testing::Not;

namespace asylo {
namespace {

class EnclaveLoggingTest : public EnclaveTest {
 public:
  using checker_t = std::function<void(const char *)>;

  void WithLogContents(const checker_t &checker) {
    WithLogContentsFrom(absl::GetFlag(FLAGS_test_tmpdir), enclave_url_,
                        checker);
  }

  static void WithLogContentsFrom(const std::string &log_directory,
                                  const std::string &enclave_url,
                                  const checker_t &checker) {
    std::string log_filename = "enclave_log";
    if (!enclave_url.empty()) {
      struct FreeDeleter {
        void operator()(void *ptr) { free(ptr); }
      };
      std::unique_ptr<char, FreeDeleter> url(strdup(enclave_url.c_str()));
      log_filename = basename(url.get());
    }
    const std::string log_file_path = log_directory + "/" + log_filename;
    FILE *file = fopen(log_file_path.c_str(), "rb");
    if (!file) {
      std::cerr << "No log file " << log_file_path << std::endl;
      // No log file means no logging happened.
      // Treat this like an empty file for checking.
      checker("");
    } else {
      // Total size of tested logging message is a bit more than 1000.
      const int buffer_size = 4096;
      auto buffer = absl::make_unique<char[]>(buffer_size);
      int bytes_read = fread(buffer.get(), sizeof(char), buffer_size, file);
      if (bytes_read < 0) {
        fclose(file);
        unlink(log_file_path.c_str());
      }
      ASSERT_GE(bytes_read, 0);

      checker(buffer.get());
      fclose(file);
      unlink(log_file_path.c_str());
    }
  }
};

TEST_F(EnclaveLoggingTest, ReadWriteTest) {
      EnclaveInput enclave_input;
      Status status = client_->EnterAndRun(enclave_input, nullptr);
      EXPECT_TRUE(status.ok());
      WithLogContents([&] (const char *buf) {
        EXPECT_THAT(buf, HasSubstr("INFO  logging_test_enclave.cc"));
        EXPECT_THAT(buf, HasSubstr("Test empty string"));
        EXPECT_THAT(buf, HasSubstr("Test logging c"));
        EXPECT_THAT(buf, HasSubstr("Test logging NULL"));
        EXPECT_THAT(buf, HasSubstr("Test logging string"));
        EXPECT_THAT(buf, HasSubstr("Test logging char array"));
        EXPECT_THAT(buf, HasSubstr("Test logging const char array"));
        EXPECT_THAT(buf, HasSubstr("Test logging int max 2147483647"));
        EXPECT_THAT(buf, HasSubstr("Test logging int min -2147483648"));
        EXPECT_THAT(buf, HasSubstr("Test logging long long max "
                                   "9223372036854775807"));
        EXPECT_THAT(buf, HasSubstr("Test logging long long min "
                                   "-9223372036854775808"));
        EXPECT_THAT(buf, HasSubstr("Test logging float max 3.40282e+38"));
        EXPECT_THAT(buf, HasSubstr("Test logging float min 1.17549e-38"));
        EXPECT_THAT(buf, HasSubstr("Test logging double max 1.79769e+308"));
        EXPECT_THAT(buf, HasSubstr("Test logging double min 2.22507e-308"));
        EXPECT_THAT(buf, HasSubstr("WARNING  logging_test_enclave.cc"));
        EXPECT_THAT(buf, HasSubstr("ERROR  logging_test_enclave.cc"));
        EXPECT_THAT(buf, HasSubstr("Test true conditional logging"));
        EXPECT_THAT(buf, Not(HasSubstr("Test false conditional logging")));
        EXPECT_THAT(buf, HasSubstr("Test VLOG below level"));
        EXPECT_THAT(buf, Not(HasSubstr("Test VLOG above level")));
      });
}

}  // namespace
}  // namespace asylo
