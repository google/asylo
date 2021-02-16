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

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/posix/io/io_manager.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::Not;

class VirtualHandlerTest : public ::testing::Test {
 public:
  void RegisterVirtualPathHandler(const std::string &path,
                                  const std::string &label) {
    io::IOManager &mgr = io::IOManager::GetInstance();
    mgr.RegisterVirtualPathHandler(path,
                                   ::absl::make_unique<TestHandler>(label));
  }

  void DeregisterVirtualPathHandler(const std::string &path) {
    io::IOManager &mgr = io::IOManager::GetInstance();
    mgr.DeregisterVirtualPathHandler(path);
  }

  StatusOr<std::string> Read(const std::string &path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
      return Status(absl::StatusCode::kInternal,
                    absl::StrCat("Error: Cannot open ", path));
    }

    char buf[128] = {};
    int count = read(fd, buf, sizeof(buf));
    if (count < 0) {
      return Status(absl::StatusCode::kInternal, "Cannot read path");
    }
    buf[sizeof(buf) - 1] = '\0';
    close(fd);
    return std::string(buf);
  }

 private:
  class TestContext : public io::IOManager::IOContext {
   public:
    TestContext(std::string label) : label_(label) {}
    virtual ~TestContext() = default;

    // Copy the label into the provided buffer
    ssize_t Read(void *buf, size_t count) override {
      char *data = reinterpret_cast<char *>(buf);
      size_t ret = label_.copy(data, count - 1);
      data[ret] = '\0';
      return ret + 1;
    }

    // Write is not allowed
    ssize_t Write(const void *buf, size_t count) override { return -1; }

    // Nothing to do for close
    int Close() override { return 0; }

   private:
    std::string label_;
  };

  class TestHandler : public io::IOManager::VirtualPathHandler {
   public:
    TestHandler(std::string label) : label_(label) {}
    virtual ~TestHandler() = default;

    std::unique_ptr<io::IOManager::IOContext> Open(const char *path, int flags,
                                                   mode_t mode) override {
      return ::absl::make_unique<TestContext>(label_);
    }

   private:
    std::string label_;
  };
};

TEST_F(VirtualHandlerTest, BasicFileMatch) {
  const std::string path = "/test/foo/bar";
  const std::string label = "BasicFileMatch";

  // Register a handler.
  RegisterVirtualPathHandler(path, label);

  // Verify that handler is used when issuing reads.
  EXPECT_THAT(Read(path), IsOkAndHolds(label));

  // Cleanup registered handler
  DeregisterVirtualPathHandler(path);
}

TEST_F(VirtualHandlerTest, BasicPrefixMatch) {
  const std::string path = "/test/foo/baz";
  const std::string label = "BasicPrefixMatch";

  // Register a handler.
  RegisterVirtualPathHandler(path, label);

  // Verify that handler is used when issuing reads.
  EXPECT_THAT(Read(absl::StrCat(path, "/qux")), IsOkAndHolds(label));

  // Cleanup registered handler.
  DeregisterVirtualPathHandler(path);
}

TEST_F(VirtualHandlerTest, PartialFileMatch) {
  const std::string path = "/test/foo/qu";
  const std::string label = "PartialFileMatch";

  // Register a handler.
  RegisterVirtualPathHandler(path, label);

  // Verify that handler isn't matched.
  auto result_or_error = Read(path + "x");
  ASSERT_THAT(result_or_error, Not(IsOk()));
  EXPECT_THAT(result_or_error, StatusIs(absl::StatusCode::kInternal,
                                        "Error: Cannot open /test/foo/qux"));

  // Cleanup registered handler.
  DeregisterVirtualPathHandler(path);
}

TEST_F(VirtualHandlerTest, OverlappingPrefixMatchFirst) {
  const std::string path1 = "/test/foo/qu";
  const std::string path2 = "/test/foo/qux";
  const std::string label1 = "OverlappingPrefixMatchFirst1";
  const std::string label2 = "OverlappingPrefixMatchFirst2";

  // Register handlers.
  RegisterVirtualPathHandler(path1, label1);
  RegisterVirtualPathHandler(path2, label2);

  // Verify the proper handler is used.
  EXPECT_THAT(Read(absl::StrCat(path1, "/bar")), IsOkAndHolds(label1));

  // Cleanup registered handlers.
  DeregisterVirtualPathHandler(path1);
  DeregisterVirtualPathHandler(path2);
}

TEST_F(VirtualHandlerTest, OverlappingPrefixMatchSecond) {
  const std::string path1 = "/test/foo/qu";
  const std::string path2 = "/test/foo/qux";
  const std::string label1 = "OverlappingPrefixMatchSecond1";
  const std::string label2 = "OverlappingPrefixMatchSecond2";

  // Register handlers.
  RegisterVirtualPathHandler(path1, label1);
  RegisterVirtualPathHandler(path2, label2);

  // Verify the proper handler is used.
  EXPECT_THAT(Read(absl::StrCat(path2, "/bar")), IsOkAndHolds(label2));

  // Cleanup registered handler.
  DeregisterVirtualPathHandler(path1);
  DeregisterVirtualPathHandler(path2);
}

TEST_F(VirtualHandlerTest, NoMatch) {
  const std::string path1 = "/test/fake";
  const std::string path2 = "/test/fakedir";
  const std::string path3 = "/test/another/fake";
  const std::string path4 = "/test/another/fakedir";

  const std::string label1 = "NoMatch1";
  const std::string label2 = "NoMatch2";
  const std::string label3 = "NoMatch3";
  const std::string label4 = "NoMatch4";

  // Register handlers.
  RegisterVirtualPathHandler(path1, label1);
  RegisterVirtualPathHandler(path2, label2);
  RegisterVirtualPathHandler(path3, label3);
  RegisterVirtualPathHandler(path4, label4);

  // Verify no handler is matched.
  ASSERT_THAT(Read("/test/blank"), Not(IsOk()));

  // CLeanup registered handlers.
  DeregisterVirtualPathHandler(path1);
  DeregisterVirtualPathHandler(path2);
  DeregisterVirtualPathHandler(path3);
  DeregisterVirtualPathHandler(path4);
}

TEST_F(VirtualHandlerTest, SiblingMatch) {
  const std::string path1 = "/test";
  const std::string path2 = "/test/fake";

  const std::string label1 = "Sibling1";
  const std::string label2 = "Sibling2";

  // Register handlers.
  RegisterVirtualPathHandler(path1, label1);
  RegisterVirtualPathHandler(path2, label2);

  // Verify proper handler is matched.
  EXPECT_THAT(Read(absl::StrCat(path1, "/example")), IsOkAndHolds(label1));

  // Cleanup registered handlers.
  DeregisterVirtualPathHandler(path1);
  DeregisterVirtualPathHandler(path2);
}

}  // namespace
}  // namespace asylo
