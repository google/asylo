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
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/test/misc/signal_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

// Pipe for stdout inside enclave. When the enclave finishes registering a
// signal handler, it writes to it to inform that it's ready to receive signal.
int pair_stdout[2];

struct RunEnclaveThreadInput {
  EnclaveClient *client;
  EnclaveInput enclave_input;
};

// Runs the enclave, waits until it returns, and checks the returned status.
void *RunEnclave(void *arg) {
  RunEnclaveThreadInput *input = reinterpret_cast<RunEnclaveThreadInput *>(arg);
  EnclaveClient *client = input->client;
  EnclaveInput enclave_input = input->enclave_input;
  EXPECT_THAT(client->EnterAndRun(enclave_input, nullptr), IsOk());
  return nullptr;
}

struct SendSignalThreadInput {
  pthread_t enclave_thread;
  int poll_fd;
  SignalTestInput::SignalTestType signal_test_type;
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
  if (input->signal_test_type == SignalTestInput::SIGACTIONMASK) {
    pthread_kill(enclave_thread, SIGUSR2);
  }
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

  // Tests signal handling inside enclave. |enclave_thread| enters the enclave,
  // registers a signal handler, and writes to pipe to inform |signal_thread|
  // that it has registered the handler and is ready to receive signal.
  // |signal_thread| then sends a signal to |enclave_thread| to test whether the
  // signal is handled correctly in the enclave.
  Status RunSignalTest(const EnclaveInput &enclave_input) {
    pthread_t enclave_thread;
    RunEnclaveThreadInput run_enclave_thread_input;
    run_enclave_thread_input.client = client_;
    run_enclave_thread_input.enclave_input = enclave_input;
    if (pthread_create(&enclave_thread, nullptr, RunEnclave,
                       &run_enclave_thread_input) != 0) {
      return LastPosixError("Failed to create enclave thread");
    }
    pthread_t signal_thread;
    SendSignalThreadInput send_signal_thread_input;
    send_signal_thread_input.enclave_thread = enclave_thread;
    send_signal_thread_input.poll_fd = pair_stdout[0];
    send_signal_thread_input.signal_test_type =
        enclave_input.GetExtension(signal_test_input).signal_test_type();
    if (pthread_create(&signal_thread, nullptr, SendSignal,
                       &send_signal_thread_input) != 0) {
      return LastPosixError("Failed to create send signal thread");
    }
    if (pthread_join(signal_thread, nullptr) != 0) {
      return LastPosixError("Failed to join send signal thread");
    }
    if (pthread_join(enclave_thread, nullptr) != 0) {
      return LastPosixError("Failed to join enclave thread");
    }
    return absl::OkStatus();
  }
};

// Test signal handled by sa_handler.
TEST_F(ActiveEnclaveSignalTest, HandlerTest) {
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::HANDLER);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

// Test signal registered with signal(2).
TEST_F(ActiveEnclaveSignalTest, SignalTest) {
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::SIGNAL);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

// Test signal handled by sa_sigaction.
TEST_F(ActiveEnclaveSignalTest, SigactionTest) {
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::SIGACTION);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

// Test signal mask. The signal is blocked inside the enclave when it's sent,
// and checks that it's not delivered. Then the enclave unblocks the signal, and
// the pending signal is delivered and handled inside the enclave. Meanwhile
// another thread running inside the enclave keeps unblocking the signal, to
// test that the signal mask is thread local.
TEST_F(ActiveEnclaveSignalTest, SignalMaskTest) {
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::SIGMASK);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

// Test sigaction(2) that registers a signal handler and specifies signals to be
// blocked during the execution of the handler. The enclave first registers a
// handler for one signal and specifies another signal to be blocked. The signal
// thread then sends both signals to the enclave. The handler of the first
// signal waits to check whether the signal handling is interrupted by the other
// signal.
TEST_F(ActiveEnclaveSignalTest, SigactionMaskTest) {
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::SIGACTIONMASK);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
}

// Test sigaction(2) that registers a signal handler and specifies an
// SA_RESETHAND flag, which resets the signal handler to default upon entry into
// the signal hander.
TEST_F(ActiveEnclaveSignalTest, ResetHandlerTest) {
  EnclaveInput enclave_input;
  enclave_input.MutableExtension(signal_test_input)
      ->set_signal_test_type(SignalTestInput::RESETHANDLER);
  EXPECT_THAT(RunSignalTest(enclave_input), IsOk());
  // Verify that the handler for SIGUSR1 is now default.
  EXPECT_EXIT(raise(SIGUSR1), ::testing::KilledBySignal(SIGUSR1), ".*");
}

}  // namespace
}  // namespace asylo
