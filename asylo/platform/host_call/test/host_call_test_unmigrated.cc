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

#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/host_call/test/enclave_test_selectors.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StrEq;

namespace asylo {
namespace host_call {
namespace {

class HostCallTest : public ::testing::Test {
 protected:
  // Loads the enclave. The function uses the factory method
  // |primitives::test::TestBackend::Get()| for loading the enclave, and the
  // type of backend (sim, remote, sgx etc.) loaded depends upon the type of
  // library included with the build that implements the abstract factory class
  // |TestBackend|.
  std::shared_ptr<primitives::Client> LoadTestEnclaveOrDie(
      StatusOr<std::unique_ptr<primitives::Client::ExitCallProvider>>
          exit_call_provider = GetHostCallHandlersMapping()) {
    ASYLO_EXPECT_OK(exit_call_provider);
    const auto client =
        primitives::test::TestBackend::Get()->LoadTestEnclaveOrDie(
            /*enclave_name=*/"host_call_test_enclave",
            std::move(exit_call_provider.ValueOrDie()));

    return client;
  }

  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    client_ = LoadTestEnclaveOrDie();
    ASSERT_FALSE(client_->IsClosed());
  }

  void TearDown() override {
    client_->Destroy();
    EXPECT_TRUE(client_->IsClosed());
  }

  std::shared_ptr<primitives::Client> client_;
};

// Tests enc_untrusted_close() by creating a file to be closed and calling
// enc_untrusted_close() from inside the enclave to close the file handle.
TEST_F(HostCallTest, TestClose) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(fcntl(fd, F_GETFD), -1);  // check fd is an open file descriptor.

  primitives::MessageWriter in;
  in.Push<int>(fd);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

// Tries closing a non-existent file handle by calling enc_untrusted_close()
// from inside the enclave.
TEST_F(HostCallTest, TestCloseNonExistentFile) {
  primitives::MessageWriter in;
  in.Push<int>(/*value=fd=*/123456);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestClose, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(-1));
}

// Tests enc_untrusted_fsync by writing to a valid file, and then running fsync
// on it. Ensures that a successful code of 0 is returned.
TEST_F(HostCallTest, TestFsync) {
  std::string test_file =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd =
      open(test_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  platform::storage::FdCloser fd_closer(fd);
  ASSERT_GE(fd, 0);
  ASSERT_NE(access(test_file.c_str(), F_OK), -1);

  // Write something to the file.
  std::string file_content = "some random content.";
  ASSERT_THAT(write(fd, file_content.c_str(), file_content.length() + 1),
              Eq(file_content.length() + 1));

  primitives::MessageWriter in;
  in.Push<int>(/*value=fd*/ fd);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestFsync, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // Should only contain return value.
  EXPECT_THAT(out.next<int>(), Eq(0));
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
