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

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include "absl/synchronization/mutex.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

// Pipe for stdout inside enclave. When the enclave finishes registering a
// signal handler, it writes to it to inform that it's ready to receive signal.
int pair_stdout[2];

// Runs the enclave, waits until it returns, and checks the returned status.
void *RunEnclave(void *arg) {
  auto client = reinterpret_cast<EnclaveClient *>(arg);
  EXPECT_THAT(client->EnterAndRun({}, nullptr), IsOk());
  return nullptr;
}

struct SendSignalThreadInput {
  pthread_t enclave_thread;
  int poll_fd;
};

// Waits till the enclave thread registers the signal handler, and sends a
// signal to the enclave thread.
void *SendSignal(void *arg) {
  SendSignalThreadInput *input = reinterpret_cast<SendSignalThreadInput *>(arg);
  pthread_t enclave_thread = input->enclave_thread;
  struct pollfd fds[1];
  memset(fds, 0, sizeof(fds));
  fds[0].fd = input->poll_fd;
  fds[0].events = POLLIN;
  // Wait till enclave thread registers signal handler and writes to pipe. Time
  // out at 30 seconds.
  EXPECT_NE(poll(fds, 1, 30000), -1);
  // Sends the signal to the enclave thread.
  pthread_kill(enclave_thread, SIGUSR1);
  return nullptr;
}

class ActiveEnclaveSignalTest : public EnclaveTest {
 public:
  void SetUp() override {
    // Create a pipe for stdout.
    CHECK_EQ(pipe(pair_stdout), 0);
    // Pass in the enclave side of the pair.
    set_stdout(pair_stdout[1]);
    SetUpBase();
  }
};

// Tests signal handling inside enclave. |enclave_thread| enters the enclave,
// registers a signal handler, and writes to pipe to inform |signal_thread| that
// it has registered the handler and is ready to receive signal. |signal_thread|
// then sends a signal to |enclave_thread| to test whether the signal is handled
// correctly in the enclave.
TEST_F(ActiveEnclaveSignalTest, SignalTest) {
  pthread_t enclave_thread;
  ASSERT_EQ(pthread_create(&enclave_thread, nullptr, RunEnclave, client_), 0);
  pthread_t signal_thread;
  SendSignalThreadInput input;
  input.enclave_thread = enclave_thread;
  input.poll_fd = pair_stdout[0];
  ASSERT_EQ(pthread_create(&signal_thread, nullptr, SendSignal, &input), 0);

  ASSERT_EQ(pthread_join(signal_thread, nullptr), 0);
  ASSERT_EQ(pthread_join(enclave_thread, nullptr), 0);
}

}  // namespace
}  // namespace asylo
