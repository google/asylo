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

#include <sys/epoll.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

constexpr const char *kTestString = "Will this go through the pipe?";
constexpr size_t kBufferSize = 1024;
constexpr size_t kNumPipes = 8;
constexpr int kRead = 0;
constexpr int kWrite = 1;

class EpollTest : public ::testing::Test {
 protected:
  Status WriteData(int fd, const char *str) {
    ssize_t num_bytes_left = strlen(str);
    while (num_bytes_left > 0) {
      ssize_t num_bytes_written = write(fd, str, num_bytes_left);
      if (num_bytes_written < 0) {
        return absl::InternalError("write() failed");
      }
      num_bytes_left -= num_bytes_written;
    }
    return absl::OkStatus();
  }

  Status ReadData(int fd, char *buf, size_t bytes_to_read) {
    while (bytes_to_read > 0) {
      int num_bytes_read = read(fd, buf, bytes_to_read);
      if (num_bytes_read < 0) {
        return absl::InternalError("read() failed");
      }
      bytes_to_read -= num_bytes_read;
    }
    return absl::OkStatus();
  }

  void WriteToPipes(const std::vector<int> &write_fds, const char *str) {
    for (int fd : write_fds) {
      EXPECT_THAT(WriteData(fd, str), IsOk());
    }
  }

  void RegisterFds(int epfd, int pipe_idx, int additional_flags = 0) {
    for (size_t i = 0; i < kNumPipes; ++i) {
      // Create the epoll event we want to add.
      struct epoll_event ev;
      ev.events = pipe_idx == 0 ? EPOLLIN : EPOLLOUT;
      ev.events |= additional_flags;
      ev.data.fd = fd_pairs_[i][pipe_idx];
      ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_ADD, fd_pairs_[i][pipe_idx], &ev),
                -1);
    }
  }

  void InitializePipes() {
    for (int i = 0; i < kNumPipes; ++i) {
      ASSERT_EQ(pipe(fd_pairs_[i]), 0);
    }
  }

  void ClosePipes() {
    for (int i = 0; i < kNumPipes; ++i) {
      close(fd_pairs_[i][0]);
      close(fd_pairs_[i][1]);
    }
  }

  // Verify that only the first kNumPipes/2 fds have registered read events.
  void VerifyReadEvents(int epfd) {
    struct epoll_event events[kNumPipes];
    int num_events = epoll_wait(epfd, events, kNumPipes, -1);
    ASSERT_NE(num_events, -1);
    EXPECT_EQ(num_events, kNumPipes / 2);
    absl::flat_hash_set<int> read_fds;
    for (int i = 0; i < num_events; ++i) {
      // Make sure that the current fd hasn't been encountered before.
      ASSERT_EQ(read_fds.find(events[i].data.fd), read_fds.end());
      read_fds.insert(events[i].data.fd);
    }
    // Make sure that the first kNumPipes/2 read fds are in our set.
    for (int i = 0; i < kNumPipes / 2; ++i) {
      ASSERT_NE(read_fds.find(fd_pairs_[i][kRead]), read_fds.end());
    }
    // Makes sure the last kNumPipes/2 read fds are not in our set.
    for (int i = kNumPipes / 2; i < kNumPipes; ++i) {
      ASSERT_EQ(read_fds.find(fd_pairs_[i][kRead]), read_fds.end());
    }
  }

  void BasicEpollTest(bool edge_triggered) {
    InitializePipes();
    int epfd = epoll_create(1);
    ASSERT_NE(epfd, -1);
    // Register all read ends from fd_pairs_ with this epoll instance.
    if (edge_triggered) {
      RegisterFds(epfd, kRead, /*additional_flags=*/EPOLLET);
    } else {
      RegisterFds(epfd, kRead);
    }
    std::vector<int> write_fds;
    // Only write to the first kNumPipes/2.
    for (int i = 0; i < kNumPipes / 2; ++i) {
      write_fds.push_back(fd_pairs_[i][kWrite]);
    }
    WriteToPipes(write_fds, kTestString);
    VerifyReadEvents(epfd);
    ASSERT_EQ(close(epfd), 0);
    ClosePipes();
  }

  void TimeoutTest(int sleep_dur, int timeout) {
    InitializePipes();
    int epfd = epoll_create(1);
    ASSERT_NE(epfd, -1);
    // Register all read ends from fd_pairs_ with this epoll instance.
    RegisterFds(epfd, kRead);
    std::vector<int> write_fds;
    // Only write to the first kNumPipes/2.
    for (int i = 0; i < kNumPipes / 2; ++i) {
      write_fds.push_back(fd_pairs_[i][kWrite]);
    }
    std::thread writer([write_fds, sleep_dur, this]() {
      std::this_thread::sleep_for(std::chrono::milliseconds(sleep_dur));
      WriteToPipes(write_fds, kTestString);
    });
    struct epoll_event events[kNumPipes];
    int num_events = epoll_wait(epfd, events, kNumPipes, timeout);
    writer.join();
    ASSERT_NE(num_events, -1);
    if (timeout < sleep_dur) {
      EXPECT_EQ(num_events, 0);
    } else {  // We must have registered at least one event.
      EXPECT_GT(num_events, 0);
    }
    ClosePipes();
  }

  void LevelEdgeBehaviorTest(bool edge_triggered) {
    size_t test_str_len = strlen(kTestString);
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    int epfd = epoll_create(1);
    ASSERT_NE(epfd, -1);
    struct epoll_event ev;
    ev.events = EPOLLIN;
    if (edge_triggered) ev.events |= EPOLLET;
    ev.data.fd = fds[kRead];
    ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_ADD, fds[kRead], &ev), -1);
    EXPECT_THAT(WriteData(fds[kWrite], kTestString), IsOk());
    struct epoll_event events[1];
    int num_events = epoll_wait(epfd, events, 1, -1);
    ASSERT_EQ(num_events, 1);
    // Read half of the string.
    char buf[kBufferSize];
    EXPECT_THAT(ReadData(fds[kRead], buf, test_str_len / 2), IsOk());
    num_events = epoll_wait(epfd, events, 1, 0);
    if (edge_triggered) {
      // There is no change in state, so we shouldn't receive a notification.
      ASSERT_EQ(num_events, 0);
    } else {
      // There is data available to read, so we should receive a notification.
      ASSERT_EQ(num_events, 1);
    }
    ASSERT_EQ(close(epfd), 0);
    ASSERT_EQ(close(fds[kRead]), 0);
    ASSERT_EQ(close(fds[kWrite]), 0);
  }

  int fd_pairs_[kNumPipes][2];
};

TEST_F(EpollTest, LevelTriggeredBasic) { BasicEpollTest(false); }

TEST_F(EpollTest, EdgeTriggeredBasic) { BasicEpollTest(true); }

TEST_F(EpollTest, EpollWaitTimeoutNotExceeded) { TimeoutTest(10, 2000); }

TEST_F(EpollTest, EpollWaitTimeoutExceeded) { TimeoutTest(500, 50); }

TEST_F(EpollTest, EpollCtlDel) {
  InitializePipes();
  int epfd = epoll_create(1);
  ASSERT_NE(epfd, -1);
  // Register all read ends from fd_pairs_ with this epoll instance.
  RegisterFds(epfd, kRead);
  // Deregister the second half of the fds using epoll_ctl
  for (int i = kNumPipes / 2; i < kNumPipes; ++i) {
    ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_DEL, fd_pairs_[i][kRead], nullptr), -1);
  }
  std::vector<int> write_fds;
  // Write to all of the fds. Only the first half should register the events
  for (int i = 0; i < kNumPipes; ++i) {
    write_fds.push_back(fd_pairs_[i][kWrite]);
  }
  WriteToPipes(write_fds, kTestString);
  VerifyReadEvents(epfd);
  ASSERT_EQ(close(epfd), 0);
  ClosePipes();
}

TEST_F(EpollTest, EpollCtlMod) {
  InitializePipes();
  int epfd = epoll_create(1);
  ASSERT_NE(epfd, -1);
  // Register all read ends from fd_pairs_ with this epoll instance.
  RegisterFds(epfd, kRead);
  // Have the second half check when the fd is available for writing, which it
  // never should be;
  for (int i = kNumPipes / 2; i < kNumPipes; ++i) {
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.fd = fd_pairs_[i][kRead];
    ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_MOD, fd_pairs_[i][kRead], &ev), -1);
  }
  std::vector<int> write_fds;
  // Write to all of the fds. Only the first half should register the events.
  for (int i = 0; i < kNumPipes; ++i) {
    write_fds.push_back(fd_pairs_[i][kWrite]);
  }
  WriteToPipes(write_fds, kTestString);
  VerifyReadEvents(epfd);
  ASSERT_EQ(close(epfd), 0);
  ClosePipes();
}

TEST_F(EpollTest, EpollCtlMix) {
  InitializePipes();
  int epfd = epoll_create(1);
  ASSERT_NE(epfd, -1);
  // Register all read ends from fd_pairs_ with this epoll instance.
  RegisterFds(epfd, kRead);
  // Deregister the second half of the fds using epoll_ctl DEL.
  for (int i = kNumPipes / 2; i < kNumPipes; ++i) {
    ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_DEL, fd_pairs_[i][kRead], nullptr), -1);
  }
  // Reregister the second half of the fds using epoll_ctl ADD.
  for (int i = kNumPipes / 2; i < kNumPipes; ++i) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd_pairs_[i][kRead];
    ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_ADD, fd_pairs_[i][kRead], &ev), -1);
  }
  // Deregister the second half of the fds using epoll_ctl MOD by making epoll
  // track these fds for write events.
  for (int i = kNumPipes / 2; i < kNumPipes; ++i) {
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.fd = fd_pairs_[i][kRead];
    ASSERT_NE(epoll_ctl(epfd, EPOLL_CTL_MOD, fd_pairs_[i][kRead], &ev), -1);
  }
  std::vector<int> write_fds;
  // Write to all of the fds. Only the first half should register the events.
  for (int i = 0; i < kNumPipes; ++i) {
    write_fds.push_back(fd_pairs_[i][kWrite]);
  }
  WriteToPipes(write_fds, kTestString);
  VerifyReadEvents(epfd);
  ASSERT_EQ(close(epfd), 0);
  ClosePipes();
}

TEST_F(EpollTest, LevelTriggeredBehavior) { LevelEdgeBehaviorTest(false); }

TEST_F(EpollTest, EdgeTriggeredBehavior) { LevelEdgeBehaviorTest(true); }

}  // namespace
}  // namespace asylo
