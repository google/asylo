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

#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/thread_annotations.h"
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "tools/cpp/runfiles/runfiles.h"
#include "asylo/test/util/exec_tester.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/status.h"

ABSL_FLAG(
    std::string, server_path, "",
    "The path to the binary that loads the Redis server inside an enclave");
ABSL_FLAG(std::string, client_path, "",
          "The path to the binary that launches the Redis client");

constexpr char kServerInitializedMessage[] = "Server initialized";
constexpr char kSnapshotTakenMessage[] =
    "Background saving terminated with success";
constexpr char kFirstKey[] = "FirstKey";
constexpr char kFirstValue[] = "FirstValue";
constexpr char kSecondKey[] = "SecondKey";
constexpr char kSecondValue[] = "SecondValue";
constexpr int kTimeout = 30;
constexpr uint64_t kNanoSecondsPerSecond = 1000000000;
constexpr uint64_t kWaitStep = 100000000;

using bazel::tools::cpp::runfiles::Runfiles;

namespace asylo {
namespace {

// An ExecTester that scans stdout for the "Server initialized" log message from
// the Redis server inside an enclave. If it finds the message, it writes to the
// address of a boolean to inform it's ready to accept requests.
// It also scans stdout for "Background saving terminated with success" log
// message. If it finds the message, it writes to an external bool to inform it
// has successfully taken a snapshot.
class RedisServerEnclaveExecTester : public asylo::experimental::ExecTester {
 public:
  RedisServerEnclaveExecTester(const std::vector<std::string> &args,
                               std::atomic<bool> *server_initialized,
                               std::atomic<bool> *snapshot_taken)
      : ExecTester(args),
        server_initialized_(server_initialized),
        snapshot_taken_(snapshot_taken) {}

 protected:
  bool CheckLine(const std::string &line) override {
    // Check if the line matches kServerInitializedMessage. If so, set
    // |*server_initialized_| to true.
    if (server_initialized_ &&
        absl::StrContains(line, kServerInitializedMessage)) {
      *server_initialized_ = true;
    } else if (snapshot_taken_ &&
               absl::StrContains(line, kSnapshotTakenMessage)) {
      // Check if the line matches kSnapshotTakenMessage. If so, set
      // |*snapshot_taken_| to true.
      *snapshot_taken_ = true;
    }
    // Print the line back to stdout in case it's needed for debugging.
    std::cout << line << std::endl;
    return true;
  }

  std::atomic<bool> *server_initialized_;
  std::atomic<bool> *snapshot_taken_;
};

std::string GetPath(const std::string &flag) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest(&error));
  return runfiles->Rlocation(absl::StrCat("com_google_asylo/", flag));
}

// An ExecTester that scans stdout for |value_| message from the Redis client.
// if it finds the message, it writes to an external bool to inform it has
// received expected output.
class RedisClientExecTester : public asylo::experimental::ExecTester {
 public:
  RedisClientExecTester(const std::vector<std::string> &args, std::string value,
                        bool *value_found)
      : ExecTester(args), value_(value), value_found_(value_found) {}

 protected:
  bool CheckLine(const std::string &line) override {
    // If a |value_| is specified, check if the line matches the expected
    // |value_|, if so, set |value_found_| to be true.
    if (value_found_ && !value_.empty() &&
        line.find(value_) != std::string::npos) {
      *value_found_ = true;
    }
    // Print the line back to stdout in case it's needed for debugging.
    std::cout << line << std::endl;
    return true;
  }

  std::string value_;
  bool *value_found_;
};

class RedisServerTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Change current working directory to temporary test directory because
    // Redis needs to access files in current working directory for snapshot
    // files.
    ASSERT_EQ(chdir(absl::GetFlag(FLAGS_test_tmpdir).c_str()), 0);

    // Use the parent process ID to make sure the socket path is unique across
    // all tests running on the current machine.
    // We can't use |TEST_TMPDIR| here, because the length of the path may
    // exceed the unix domain socket path limit.
    domain_socket_path_ = absl::StrCat("/tmp/redis_", getpid(), ".sock");

    StartServer();

    // Saves the client path.
    client_path_ = GetPath(absl::GetFlag(FLAGS_client_path));
  }

  void TearDown() override { ShutdownServer(); }

 protected:
  // Spawns the Redis server subprocess and waits for it to inform it's ready.
  // Fails if the log message is not not seen in 30 seconds.
  void StartServer() {
    std::string server_path = GetPath(absl::GetFlag(FLAGS_server_path));
    // Use a unix domain socket to avoid conflicting port when multiple tests
    // are running on the same machine.
    const std::vector<std::string> server_argv({server_path, "--port", "0",
                                                "--unixsocket",
                                                domain_socket_path_.c_str()});
    server_initialized_ = false;

    // Run the server ExecTester in a separate thread.
    server_thread_ = absl::make_unique<std::thread>(
        [this](const std::vector<std::string> &argv) {
          RedisServerEnclaveExecTester server_runner(argv, &server_initialized_,
                                                     &snapshot_taken_);
          server_runner.Run(/*input=*/"", &server_exit_status_);
        },
        server_argv);

    // Wait for the server to be initialized. Timeout at 30 seconds.
    for (uint64_t i = 0; i < kTimeout * kNanoSecondsPerSecond / kWaitStep;
         ++i) {
      if (server_initialized_) {
        break;
      }
      struct timespec tm;
      tm.tv_sec = 0;
      tm.tv_nsec = kWaitStep;
      nanosleep(&tm, /*rem=*/nullptr);
    }

    ASSERT_TRUE(server_initialized_) << "Server initialize timeout";
  }

  // Spawns the Redis Client subprocess to shutdown the server.
  void ShutdownServer() {
    int client_exit_status;
    int *exit_status_address = &client_exit_status;
    const std::vector<std::string> client_shutdown_argv(
        {client_path_, "-s", domain_socket_path_.c_str(), "shutdown"});
    auto client_thread_shutdown = absl::make_unique<std::thread>(
        [exit_status_address](const std::vector<std::string> &argv) {
          RedisClientExecTester client_runner(argv, /*value=*/"",
                                              /*value_found=*/nullptr);
          client_runner.Run(/*input=*/"", exit_status_address);
        },
        client_shutdown_argv);
    client_thread_shutdown->join();
    CheckExitStatus(client_exit_status);
    server_thread_->join();
    CheckExitStatus(server_exit_status_);
  }

  // Checks whether the subprocess exit normally.
  void CheckExitStatus(int exit_status) {
    ASSERT_TRUE(WIFEXITED(exit_status))
        << (WIFSIGNALED(exit_status)
                ? absl::StrCat("Subprocess killed by signal ",
                               WTERMSIG(exit_status))
                : "Subprocess ended abnormally");
    EXPECT_EQ(WEXITSTATUS(exit_status), 0)
        << absl::StrCat("Subprocess exited with non-zero status ",
                        WEXITSTATUS(exit_status));
  }

  std::unique_ptr<std::thread> server_thread_;
  std::atomic<bool> server_initialized_;
  std::atomic<bool> snapshot_taken_;
  std::string client_path_;
  std::string domain_socket_path_;
  int server_exit_status_;
};

// Tests Redis server inside an enclave by set/get a key from a client.
TEST_F(RedisServerTest, SetGetTest) {
  // Spawn a Redis client to set a key.
  const std::vector<std::string> client_set_key_argv(
      {client_path_, "-s", domain_socket_path_.c_str(), "set",
       std::string(kFirstKey), std::string(kFirstValue)});
  int exit_status;
  int *exit_status_address = &exit_status;
  auto client_thread_set_key = absl::make_unique<std::thread>(
      [exit_status_address](const std::vector<std::string> &argv) {
        RedisClientExecTester client_runner(argv, /*value=*/"",
                                            /*value_found=*/nullptr);
        client_runner.Run(/*input=*/"", exit_status_address);
      },
      client_set_key_argv);
  client_thread_set_key->join();
  CheckExitStatus(exit_status);

  // Spawn a Redis client to get a key and confirm the value matches
  // expectation.
  const std::vector<std::string> client_get_key_argv(
      {client_path_, "-s", domain_socket_path_.c_str(), "get",
       std::string(kFirstKey)});
  bool got_value = false;
  bool *got_value_address = &got_value;
  auto client_thread_get_key = absl::make_unique<std::thread>(
      [exit_status_address,
       got_value_address](const std::vector<std::string> &argv) {
        RedisClientExecTester client_runner(argv, std::string(kFirstValue),
                                            got_value_address);
        client_runner.Run(/*input=*/"", exit_status_address);
      },
      client_get_key_argv);
  client_thread_get_key->join();
  CheckExitStatus(exit_status);
  EXPECT_TRUE(got_value);
}

// Tests Snapshot of Redis server inside an enclave by set a key, save a
// snapshot, then restart the server to confirm the that snapshot loaded in the
// new server contains the expected key and value.
TEST_F(RedisServerTest, Snapshot) {
  snapshot_taken_ = false;
  // Spawn a Redis client to config the server to take a snapshot if there's one
  // change in one second.
  const std::vector<std::string> client_set_save_argv(
      {client_path_, "-s", domain_socket_path_.c_str(), "CONFIG", "SET", "save",
       "1 1"});
  int exit_status;
  int *exit_status_address = &exit_status;
  auto client_thread_set_save = absl::make_unique<std::thread>(
      [exit_status_address](const std::vector<std::string> &argv) {
        RedisClientExecTester client_runner(argv, /*value=*/"",
                                            /*value_found=*/nullptr);
        client_runner.Run(/*input=*/"", exit_status_address);
      },
      client_set_save_argv);
  client_thread_set_save->join();
  CheckExitStatus(exit_status);

  // Spawn a Redis client to set a key.
  const std::vector<std::string> client_set_key_argv(
      {client_path_, "-s", domain_socket_path_.c_str(), "set",
       std::string(kSecondKey), std::string(kSecondValue)});
  auto client_thread_set_key = absl::make_unique<std::thread>(
      [exit_status_address](const std::vector<std::string> &argv) {
        RedisClientExecTester client_runner(argv, /*value=*/"",
                                            /*value_found=*/nullptr);
        client_runner.Run(/*input=*/"", exit_status_address);
      },
      client_set_key_argv);
  client_thread_set_key->join();
  CheckExitStatus(exit_status);

  // Waits until the snapshot is taken by the server. Timeout at 30 seconds.
  for (uint64_t i = 0; i < kTimeout * kNanoSecondsPerSecond / kWaitStep; ++i) {
    if (snapshot_taken_) {
      break;
    }
    struct timespec tm;
    tm.tv_sec = 0;
    tm.tv_nsec = kWaitStep;
    nanosleep(&tm, /*rem=*/nullptr);
  }
  ASSERT_TRUE(snapshot_taken_) << "Snapshot timeout";

  // Restart the server to load the snapshot.
  ShutdownServer();
  StartServer();

  // Spawns a Redis client to confirm that the snapshot contains the expected
  // key and value.
  const std::vector<std::string> client_get_key_argv(
      {client_path_, "-s", domain_socket_path_.c_str(), "get",
       std::string(kSecondKey)});
  bool got_value = false;
  bool *got_value_address = &got_value;
  auto client_thread_get_key = absl::make_unique<std::thread>(
      [exit_status_address,
       got_value_address](const std::vector<std::string> &argv) {
        RedisClientExecTester client_runner(argv, std::string(kSecondValue),
                                            got_value_address);
        client_runner.Run(/*input=*/"", exit_status_address);
      },
      client_get_key_argv);
  client_thread_get_key->join();
  CheckExitStatus(exit_status);

  EXPECT_TRUE(got_value);
}

}  // namespace
}  // namespace asylo
