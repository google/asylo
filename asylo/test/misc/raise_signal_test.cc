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

#include <signal.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

static bool signal_handled = false;

void HandleSignal(int signum) {
  if (signum == SIGUSR1) {
    signal_handled = true;
  }
}

// Registers a signal handler for SIGUSR1, raises it, and checks whether it's
// handled.
TEST(SignalTest, RaiseSignal) {
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = &HandleSignal;
  struct sigaction oldact;
  sigaction(SIGUSR1, &act, &oldact);
  raise(SIGUSR1);
  EXPECT_TRUE(signal_handled);
}

}  // namespace
}  // namespace asylo
