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

#include "asylo/platform/primitives/message.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/primitives/extent.h"

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace primitives {
namespace {

constexpr size_t kNumParams = 10;

TEST(MessageTest, EmptyWriterReaderTest) {
  MessageWriter writer;
  EXPECT_TRUE(writer.empty());
  EXPECT_THAT(writer.size(), Eq(0));

  size_t message_len = writer.MessageSize();
  void *message = malloc(message_len);
  writer.Write(message);

  MessageReader reader(message, message_len);
  free(message);
  EXPECT_THAT(reader.size(), Eq(0));
}

TEST(MessageTest, PushPopDataByValue) {
  MessageWriter writer;
  writer.PushByCopy(Extent{"hello", strlen("hello") + 1});
  writer.PushByCopy(Extent{"world", strlen("world") + 1});
  writer.Push(1);
  writer.Push(2);

  EXPECT_FALSE(writer.empty());
  EXPECT_THAT(writer.size(), Eq(4));

  size_t message_len = writer.MessageSize();
  void *message = malloc(message_len);
  writer.Write(message);

  MessageReader reader(message, message_len);
  free(message);

  EXPECT_THAT(reader.size(), Eq(4));
  EXPECT_THAT(reader.next().As<char>(), StrEq("hello"));
  EXPECT_THAT(reader.next().As<char>(), StrEq("world"));
  EXPECT_THAT(*(reader.next().As<int>()), Eq(1));
  EXPECT_THAT(*(reader.next().As<int>()), Eq(2));
}

TEST(MessageTest, PushPopNums) {
  MessageWriter writer;
  for (int i = 0; i < kNumParams; ++i) {
    writer.Push(i);
  }
  EXPECT_FALSE(writer.empty());
  EXPECT_THAT(writer.size(), Eq(kNumParams));

  size_t message_len = writer.MessageSize();
  void *message = malloc(message_len);
  writer.Write(message);

  MessageReader reader(message, message_len);
  free(message);

  EXPECT_THAT(reader.size(), Eq(kNumParams));
  for (int i = 0; i < kNumParams; ++i) {
    EXPECT_THAT(*(reader.next().As<int>()), Eq(i));
  }
}

TEST(MessageTest, PushByReferenceTest) {
  const char *hello = "hello";
  const char *world = "world";
  MessageWriter writer;
  writer.PushByReference(Extent{hello, strlen(hello) + 1});
  writer.PushByReference(Extent{world, strlen(world) + 1});

  EXPECT_FALSE(writer.empty());
  EXPECT_THAT(writer.size(), Eq(2));

  size_t message_len = writer.MessageSize();
  void *message = malloc(message_len);
  writer.Write(message);

  MessageReader reader(message, message_len);
  free(message);

  EXPECT_THAT(reader.size(), Eq(2));
  EXPECT_THAT(reader.next().As<char>(), StrEq(hello));
  EXPECT_THAT(reader.next().As<char>(), StrEq(world));
}

TEST(MessageTest, PushPopStrings) {
  MessageWriter writer;
  std::string hello("hello"), world("world");
  writer.Push(hello);
  writer.Push(world);

  EXPECT_FALSE(writer.empty());
  EXPECT_THAT(writer.size(), Eq(2));

  size_t message_len = writer.MessageSize();
  void *message = malloc(message_len);
  writer.Write(message);

  MessageReader reader(message, message_len);
  free(message);

  EXPECT_THAT(reader.size(), Eq(2));
  EXPECT_THAT(reader.next().As<char>(), StrEq(hello));
  EXPECT_THAT(reader.next().As<char>(), StrEq(world));
}


}  // namespace
}  // namespace primitives
}  // namespace asylo
