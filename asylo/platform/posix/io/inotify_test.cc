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
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {
namespace {

const char *str = "Testing inotify.";
constexpr size_t kSleepDur = 100;
constexpr size_t kEventBufSize = 4096;

class InotifyTest : public ::testing::Test {
 protected:
  InotifyTest() {
    file1_ = absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/file1.out");
    file2_ = absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/file2.out");
    file3_ = absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/file3.out");
    // Remove files in case test is run on the same machine.
    remove(file1_.c_str());
    remove(file2_.c_str());
    remove(file3_.c_str());
    // Open files.
    fd1_ = open(file1_.c_str(), O_CREAT | O_RDWR, 0644);
    fd2_ = open(file2_.c_str(), O_CREAT | O_RDWR, 0644);
    fd3_ = open(file3_.c_str(), O_CREAT | O_RDWR, 0644);
    infd_ = inotify_init();
    EXPECT_GT(infd_, 0);
  }

  void CloseFds() {
    close(fd1_);
    close(fd2_);
    close(fd3_);
    close(infd_);
  }

  std::string file1_;
  std::string file2_;
  std::string file3_;
  int fd1_;
  int fd2_;
  int fd3_;
  int infd_;
};

TEST_F(InotifyTest, SingleFileWrite) {
  int wd1 = inotify_add_watch(infd_, file1_.c_str(), IN_MODIFY);
  ASSERT_GT(wd1, 0);
  size_t len = strlen(str);
  EXPECT_EQ(write(fd1_, str, len), len);
  char buf[sizeof(struct inotify_event) + PATH_MAX + 1];
  // Check to see if the event is registered by inotify.
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  struct inotify_event *event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_MODIFY);
  EXPECT_EQ(event->len, 0);
  CloseFds();
}

TEST_F(InotifyTest, SingleFileWriteBlock) {
  int wd1 = inotify_add_watch(infd_, file1_.c_str(), IN_MODIFY);
  ASSERT_GT(wd1, 0);
  size_t len = strlen(str);
  std::thread writer([this, len] {
    std::this_thread::sleep_for(std::chrono::milliseconds(kSleepDur));
    EXPECT_EQ(write(fd1_, str, len), len);
  });
  char buf[sizeof(struct inotify_event) + PATH_MAX + 1];
  // Check to see if the event is registered by inotify.
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  writer.join();
  struct inotify_event *event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_MODIFY);
  EXPECT_EQ(event->len, 0);
  CloseFds();
}

TEST_F(InotifyTest, SingleFileClosed) {
  int wd1 = inotify_add_watch(infd_, file1_.c_str(), IN_CLOSE_WRITE);
  ASSERT_GT(wd1, 0);
  EXPECT_EQ(close(fd1_), 0);
  char buf[sizeof(struct inotify_event) + PATH_MAX + 1];
  // Check to see if the event is registered by inotify.
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  struct inotify_event *event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_CLOSE_WRITE);
  EXPECT_EQ(event->len, 0);
  close(fd2_);
  close(fd3_);
  close(infd_);
}

TEST_F(InotifyTest, SingleFileRead) {
  int wd1 = inotify_add_watch(infd_, file1_.c_str(), IN_ACCESS);
  ASSERT_GT(wd1, 0);
  size_t len = strlen(str);
  EXPECT_EQ(write(fd1_, str, len), len);
  char *read_buf = static_cast<char *>(malloc(len));
  int fd1_read = open(file1_.c_str(), O_RDONLY, 0644);
  EXPECT_GT(read(fd1_read, read_buf, len), 0);
  close(fd1_read);
  free(read_buf);
  char buf[sizeof(struct inotify_event) + PATH_MAX + 1];
  // Check to see if the event is registered by inotify.
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  struct inotify_event *event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_ACCESS);
  EXPECT_EQ(event->len, 0);
  CloseFds();
}

TEST_F(InotifyTest, SingleFileWriteDir) {
  int wd1 = inotify_add_watch(infd_, absl::GetFlag(FLAGS_test_tmpdir).c_str(),
                              IN_MODIFY);
  ASSERT_GT(wd1, 0);
  size_t len = strlen(str);
  EXPECT_EQ(write(fd1_, str, len), len);
  char buf[sizeof(struct inotify_event) + PATH_MAX + 1];
  // Check to see if the event is registered by inotify.
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  struct inotify_event *event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_MODIFY);
  // Check name attribute as well.
  EXPECT_EQ(strcmp(event->name, "file1.out"), 0);
  CloseFds();
}

TEST_F(InotifyTest, NonBlock) {
  close(infd_);
  infd_ = inotify_init1(IN_NONBLOCK);
  int wd1 = inotify_add_watch(infd_, file1_.c_str(), IN_ACCESS);
  ASSERT_GT(wd1, 0);
  char buf[sizeof(struct inotify_event) + PATH_MAX + 1];
  // No event should be registered, read() should return immediately.
  EXPECT_EQ(read(infd_, buf, sizeof(buf)), -1);
  EXPECT_EQ(errno, EAGAIN);
  CloseFds();
}

TEST_F(InotifyTest, MultipleEvents) {
  int wds[3];
  wds[0] = inotify_add_watch(infd_, file1_.c_str(), IN_MODIFY | IN_CLOSE_WRITE);
  ASSERT_GT(wds[0], 0);
  wds[1] = inotify_add_watch(infd_, file2_.c_str(), IN_MODIFY | IN_CLOSE_WRITE);
  ASSERT_GT(wds[1], 0);
  wds[2] = inotify_add_watch(infd_, file3_.c_str(), IN_MODIFY | IN_CLOSE_WRITE);
  ASSERT_GT(wds[2], 0);
  size_t len = strlen(str);
  EXPECT_EQ(write(fd1_, str, len), len);
  EXPECT_EQ(write(fd2_, str, len), len);
  EXPECT_EQ(write(fd3_, str, len), len);
  EXPECT_EQ(close(fd1_), 0);
  EXPECT_EQ(close(fd2_), 0);
  EXPECT_EQ(close(fd3_), 0);
  char buf[kEventBufSize];
  // Check to see if the events are registered by inotify.
  ssize_t bytes_read = read(infd_, buf, sizeof(buf));
  ASSERT_GT(bytes_read, 0);
  EXPECT_EQ(bytes_read, 6 * sizeof(struct inotify_event));
  char *curr_event_ptr = buf;
  for (int i = 0; i < sizeof(wds) / sizeof(int); ++i) {
    struct inotify_event *curr_event =
        reinterpret_cast<struct inotify_event *>(curr_event_ptr);
    EXPECT_EQ(curr_event->wd, wds[i]);
    EXPECT_TRUE(curr_event->mask & IN_MODIFY);
    EXPECT_EQ(curr_event->len, 0);
    curr_event_ptr += sizeof(struct inotify_event);
  }
  for (int i = 0; i < sizeof(wds) / sizeof(int); ++i) {
    struct inotify_event *curr_event =
        reinterpret_cast<struct inotify_event *>(curr_event_ptr);
    EXPECT_EQ(curr_event->wd, wds[i]);
    EXPECT_TRUE(curr_event->mask & IN_CLOSE_WRITE);
    EXPECT_EQ(curr_event->len, 0);
    curr_event_ptr += sizeof(struct inotify_event);
  }
  close(infd_);
}

TEST_F(InotifyTest, EventsQueued) {
  int wd1 =
      inotify_add_watch(infd_, file1_.c_str(), IN_MODIFY | IN_CLOSE_WRITE);
  ASSERT_GT(wd1, 0);
  size_t len = strlen(str);
  EXPECT_EQ(write(fd1_, str, len), len);
  EXPECT_EQ(close(fd1_), 0);
  // This buffer can accommodate only one event. However, the enclave version
  // creates a buffer of size sizeof(struct inotify_event) + NAME_MAX + 1, which
  // can accommodate multiple events. Thus, the enclave will be forced to queue
  // up some events. We are required to read from infd_ multiple times to
  // register all of the events.
  char buf[sizeof(struct inotify_event)];
  // Check to see if the events are registered by inotify.
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  struct inotify_event *event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_MODIFY);
  EXPECT_EQ(event->len, 0);
  ASSERT_GT(read(infd_, buf, sizeof(buf)), 0);
  event = reinterpret_cast<struct inotify_event *>(buf);
  EXPECT_EQ(event->wd, wd1);
  EXPECT_TRUE(event->mask & IN_CLOSE_WRITE);
  EXPECT_EQ(event->len, 0);
  close(fd2_);
  close(fd3_);
  close(infd_);
}

TEST_F(InotifyTest, BufferTooSmall) {
  int wd1 = inotify_add_watch(infd_, file1_.c_str(), IN_MODIFY);
  ASSERT_GT(wd1, 0);
  size_t len = strlen(str);
  EXPECT_EQ(write(fd1_, str, len), len);
  // Make the buffer one byte too small.
  char buf[sizeof(struct inotify_event) - 1];
  // Check to see if the event is registered by inotify.
  EXPECT_EQ(read(infd_, buf, sizeof(buf)), -1);
  EXPECT_EQ(errno, EINVAL);
  CloseFds();
}

}  // namespace
}  // namespace asylo
