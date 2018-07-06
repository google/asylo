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

#include "asylo/crypto/util/byte_container_view.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/bytes.h"

namespace asylo {
namespace {

constexpr char kArr[] = "Mary had a little lamb, its fleece was white as snow";
constexpr size_t kSize = sizeof(kArr) - 1;

// A typed test fixture is used for tests that require a single type object.
template <typename T>
class TypedByteContainerViewTest : public ::testing::Test {
 public:
};

typedef ::testing::Types<SafeBytes<kSize>, UnsafeBytes<kSize>,
                         std::vector<uint8_t>, std::vector<char>, std::string,
                         std::basic_string<uint8_t, std::char_traits<uint8_t>>>
    MyTypes;
TYPED_TEST_CASE(TypedByteContainerViewTest, MyTypes);

TYPED_TEST(TypedByteContainerViewTest, DataMethod) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);

  EXPECT_EQ(static_cast<const void *>(view.data()),
            static_cast<const void *>(container.data()));
}

TYPED_TEST(TypedByteContainerViewTest, SizeMethod) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);

  EXPECT_EQ(view.size(), container.size());
}

TYPED_TEST(TypedByteContainerViewTest, SubscriptOperator) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);

  for (int i = 0; i < view.size(); i++) {
    EXPECT_EQ(static_cast<const void *>(&view[i]),
              static_cast<const void *>(&container[i]));
  }
}

TYPED_TEST(TypedByteContainerViewTest, AtMethod) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);

  for (int i = 0; i < view.size(); i++) {
    EXPECT_EQ(static_cast<const void *>(&view.at(i)),
              static_cast<const void *>(&container.at(i)));
  }
}

TYPED_TEST(TypedByteContainerViewTest, Iterator) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);
  auto it1 = view.begin();
  auto it2 = container.begin();

  while (it1 != view.end()) {
    EXPECT_EQ(static_cast<const void *>(&(*it1)),
              static_cast<const void *>(&(*it2)));
    ++it1;
    ++it2;
  }
}

TYPED_TEST(TypedByteContainerViewTest, ConstIterator) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);
  auto it1 = view.cbegin();
  auto it2 = container.cbegin();

  while (it1 != view.cend()) {
    EXPECT_EQ(static_cast<const void *>(&(*it1)),
              static_cast<const void *>(&(*it2)));
    ++it1;
    ++it2;
  }
}

TYPED_TEST(TypedByteContainerViewTest, ReverseIterator) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);
  auto it1 = view.rbegin();
  auto it2 = container.rbegin();

  while (it1 != view.rend()) {
    EXPECT_EQ(static_cast<const void *>(&(*it1)),
              static_cast<const void *>(&(*it2)));
    ++it1;
    ++it2;
  }
}

TYPED_TEST(TypedByteContainerViewTest, ConstReverseIterator) {
  TypeParam container(kArr, kArr + kSize);
  ByteContainerView view(container);
  auto it1 = view.crbegin();
  auto it2 = container.crbegin();

  while (it1 != view.crend()) {
    EXPECT_EQ(static_cast<const void *>(&(*it1)),
              static_cast<const void *>(&(*it2)));
    ++it1;
    ++it2;
  }
}

}  // namespace
}  // namespace asylo
