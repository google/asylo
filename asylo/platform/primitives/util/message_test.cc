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

#include "asylo/platform/primitives/util/message.h"

#include <cstddef>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StrEq;

namespace asylo {
namespace primitives {
namespace {

constexpr size_t kNumBuffer = 10;

// Builds a MessageReader from |writer|.
MessageReader BuildMessageReader(const MessageWriter &writer) {
  const size_t size = writer.MessageSize();
  const auto buffer = absl::make_unique<char[]>(size);
  writer.Serialize(buffer.get());

  MessageReader reader;
  reader.Deserialize(buffer.get(), size);
  return reader;
}

TEST(MessageTest, NullReaderTest) {
  MessageReader reader;
  EXPECT_THAT(reader, IsEmpty());
  EXPECT_THAT(reader, SizeIs(0));
}

TEST(MessageTest, EmptyWriterReaderTest) {
  MessageWriter writer;
  EXPECT_THAT(writer, IsEmpty());
  EXPECT_THAT(writer, SizeIs(0));

  const size_t size = writer.MessageSize();
  const auto buffer = absl::make_unique<char[]>(size);
  writer.Serialize(buffer.get());

  MessageReader reader;
  reader.Deserialize(buffer.get(), size);
  EXPECT_THAT(reader, IsEmpty());
  EXPECT_THAT(reader, SizeIs(0));
}

TEST(MessageTest, PushPopDataByValue) {
  MessageWriter writer;
  writer.Push(1);
  writer.Push(2);
  writer.PushByCopy(Extent{"hello", strlen("hello") + 1});
  writer.PushByCopy(Extent{"world", strlen("world") + 1});

  EXPECT_THAT(writer, Not(IsEmpty()));
  EXPECT_THAT(writer, SizeIs(4));

  const size_t size = writer.MessageSize();
  auto buffer = absl::make_unique<char[]>(size);
  writer.Serialize(buffer.get());

  MessageReader reader;
  reader.Deserialize(buffer.get(), size);

  ASSERT_THAT(reader, Not(IsEmpty()));
  ASSERT_THAT(reader, SizeIs(4));
  EXPECT_THAT(reader.peek<int>(), Eq(1));
  EXPECT_THAT(*(reader.next().As<int>()), Eq(1));
  EXPECT_THAT(reader.peek<int>(), Eq(2));
  EXPECT_THAT(*(reader.next().As<int>()), Eq(2));
  EXPECT_THAT(reader.next().As<char>(), StrEq("hello"));
  EXPECT_THAT(reader.next().As<char>(), StrEq("world"));
  EXPECT_THAT(reader.hasNext(), Eq(false));
}

TEST(MessageTest, ExtendMessageWriterFromOther) {
  MessageWriter writer, other;
  for (int i = 0; i < kNumBuffer / 2; ++i) {
    writer.Push(i);                  // 0, 1, 2, 3, 4
    other.Push(kNumBuffer / 2 + i);  // 5, 6, 7, 8, 9
  }

  writer.Extend(other);

  MessageReader reader = BuildMessageReader(writer);

  ASSERT_THAT(reader, Not(IsEmpty()));
  ASSERT_THAT(reader, SizeIs(kNumBuffer));
  for (int i = 0; i < kNumBuffer; ++i) {
    ASSERT_TRUE(reader.hasNext());
    EXPECT_THAT(reader.peek<int>(), Eq(i));
    EXPECT_THAT(reader.next<int>(), Eq(i));
  }
}

TEST(MessageTest, PushPopNums) {
  MessageWriter writer;
  for (int i = 0; i < kNumBuffer; ++i) {
    writer.Push(i);
  }
  EXPECT_THAT(writer, Not(IsEmpty()));
  EXPECT_THAT(writer, SizeIs(kNumBuffer));

  const size_t size = writer.MessageSize();
  const auto buffer = absl::make_unique<char[]>(size);
  writer.Serialize(buffer.get());

  MessageReader reader;
  reader.Deserialize(buffer.get(), size);

  ASSERT_THAT(reader, Not(IsEmpty()));
  ASSERT_THAT(reader, SizeIs(kNumBuffer));
  for (int i = 0; i < kNumBuffer; ++i) {
    ASSERT_TRUE(reader.hasNext());
    EXPECT_THAT(*(reader.next().As<int>()), Eq(i));
  }
}

TEST(MessageTest, PushByReferenceTest) {
  const char *hello = "hello";
  const char *world = "world";
  MessageWriter writer;
  writer.PushByReference(Extent{hello, strlen(hello) + 1});
  writer.PushByReference(Extent{world, strlen(world) + 1});

  EXPECT_THAT(writer, Not(IsEmpty()));
  EXPECT_THAT(writer, SizeIs(2));

  const size_t size = writer.MessageSize();
  const auto buffer = absl::make_unique<char[]>(size);
  writer.Serialize(buffer.get());

  MessageReader reader;
  reader.Deserialize(buffer.get(), size);

  ASSERT_THAT(reader, Not(IsEmpty()));
  ASSERT_THAT(reader, SizeIs(2));
  EXPECT_THAT(reader.next().As<char>(), StrEq(hello));
  EXPECT_THAT(reader.next().As<char>(), StrEq(world));
  EXPECT_THAT(reader.hasNext(), Eq(false));
}

// Ensure we can read and write strings, both for std::string and string
// literals.
TEST(MessageTest, PushPopStrings) {
  MessageWriter writer;
  writer.PushString(std::string("hello"));
  writer.PushString(std::string("world"));
  writer.PushString("goodnight");
  writer.PushString("moon");
  EXPECT_THAT(writer, Not(IsEmpty()));
  EXPECT_THAT(writer, SizeIs(4));

  const size_t size = writer.MessageSize();
  const auto buffer = absl::make_unique<char[]>(size);
  writer.Serialize(buffer.get());

  MessageReader reader;
  reader.Deserialize(buffer.get(), size);

  ASSERT_THAT(reader, Not(IsEmpty()));
  ASSERT_THAT(reader, SizeIs(4));
  EXPECT_THAT(reader.next().As<char>(), StrEq("hello"));
  EXPECT_THAT(reader.next().As<char>(), StrEq("world"));
  EXPECT_THAT(reader.next().As<char>(), StrEq("goodnight"));
  EXPECT_THAT(reader.next().As<char>(), StrEq("moon"));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
