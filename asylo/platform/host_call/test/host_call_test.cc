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

// Tests enc_untrusted_access() by creating a file and calling
// enc_untrusted_access() from inside the enclave and verifying its return
// value.
TEST_F(HostCallTest, TestAccess) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/test_file.tmp");
  int fd = creat(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  ASSERT_GE(fd, 0);

  primitives::MessageWriter in;
  in.Push(path);
  in.Push<int>(/*value=mode=*/R_OK | W_OK);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), access(path.c_str(), R_OK | W_OK));
}

// Tests enc_untrusted_access() against a non-existent path.
TEST_F(HostCallTest, TestAccessNonExistentPath) {
  const char *path = "illegal_path";

  primitives::MessageWriter in;
  in.Push(primitives::Extent{path, strlen(path) + 1});
  in.Push<int>(/*value=mode=*/F_OK);

  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestAccess, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<int>(), access(path, F_OK));
}

// Tests enc_untrusted_getpid() by calling it from inside the enclave and
// verifying its return value against pid obtained from native system call.
TEST_F(HostCallTest, TestGetpid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getpid()));
}

// Tests enc_untrusted_getppid() by calling it from inside the enclave and
// verifying its return value against ppid obtained from native system call.
TEST_F(HostCallTest, TestGetPpid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetPpid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getppid()));
}

// Tests enc_untrusted_setsid() by calling it from inside the enclave and
// verifying its return value against sid obtained from getsid(0), which
// gets the sid of the current process.
TEST_F(HostCallTest, TestSetSid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestSetSid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain return value.
  EXPECT_THAT(out.next<pid_t>(), Eq(getsid(0)));
}

// Tests enc_untrusted_getgid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getgid().
TEST_F(HostCallTest, TestGetgid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetGid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<gid_t>(), Eq(getgid()));
}

// Tests enc_untrusted_geteuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native geteuid().
TEST_F(HostCallTest, TestGetEuid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEuid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<uid_t>(), Eq(geteuid()));
}

// Tests enc_untrusted_getegid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getegid().
TEST_F(HostCallTest, TestGetEgid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetEgid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<gid_t>(), Eq(getegid()));
}

// Tests enc_untrusted_getuid() by making the host call from inside the enclave
// and comparing the result with the value obtained from native getuid().
TEST_F(HostCallTest, TestGetuid) {
  primitives::MessageWriter in;
  primitives::MessageReader out;
  ASYLO_ASSERT_OK(client_->EnclaveCall(kTestGetUid, &in, &out));
  ASSERT_THAT(out, SizeIs(1));  // should only contain the return value.
  EXPECT_THAT(out.next<uid_t>(), Eq(getuid()));
}

}  // namespace
}  // namespace host_call
}  // namespace asylo
