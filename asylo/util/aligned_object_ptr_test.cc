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

#include "asylo/util/aligned_object_ptr.h"

#include <string>

#include <gtest/gtest.h>
#include "absl/base/attributes.h"
#include "absl/container/flat_hash_map.h"

namespace asylo {
namespace {

struct TestStruct {
  uint64_t a;
  uint32_t b;
} ABSL_ATTRIBUTE_PACKED;  // Use ABSL_ATTRIBUTE_PACKED to make sure that the
                          // struct does not have a nice, integer-power-of-two
                          // size.

class TestClass {
 public:
  TestClass(uint64_t a, uint32_t b) : a_{a}, b_{b} {}
  TestClass() : a_{0}, b_{0} {}

  uint64_t get_a() { return a_; }
  uint32_t get_b() { return b_; }

 private:
  uint64_t a_;
  uint32_t b_;
};

constexpr uint64_t kAlignSizes[] = {
    1ULL << 0, 1ULL << 5, 1ULL << 9, 1ULL << 12, 1ULL << 16, 1ULL << 20,
    // A couple of non-integer-power-of-two sizes
    48, 72};

// A test fixture is used for naming consistency and future extensibility.
class AlignedObjectPtrTest : public ::testing::Test {};

template <class T, size_t Align>
void CheckAlign(const AlignedObjectPtr<T, Align> &t) {
  uintptr_t addr = reinterpret_cast<uintptr_t>(t.get());
  EXPECT_EQ(addr % Align, 0);
  using TmpType = AlignedObjectPtr<T, Align>;
  EXPECT_TRUE(TmpType::IsAligned(t.get()));
}

// Test AignedObjectPtr with an integer object type.
TEST_F(AlignedObjectPtrTest, Uint64_tAlign) {
  AlignedObjectPtr<uint64_t, kAlignSizes[0]> num0;
  EXPECT_TRUE(num0);
  CheckAlign(num0);

  AlignedObjectPtr<uint64_t, kAlignSizes[1]> num1;
  EXPECT_TRUE(num1);
  CheckAlign(num1);

  AlignedObjectPtr<uint64_t, kAlignSizes[2]> num2;
  EXPECT_TRUE(num2);
  CheckAlign(num2);

  AlignedObjectPtr<uint64_t, kAlignSizes[3]> num3;
  EXPECT_TRUE(num3);
  CheckAlign(num3);

  AlignedObjectPtr<uint64_t, kAlignSizes[4]> num4;
  EXPECT_TRUE(num4);
  CheckAlign(num4);

  AlignedObjectPtr<uint64_t, kAlignSizes[5]> num5;
  EXPECT_TRUE(num5);
  CheckAlign(num5);

  AlignedObjectPtr<uint64_t, kAlignSizes[6]> num6;
  EXPECT_TRUE(num6);
  CheckAlign(num6);

  AlignedObjectPtr<uint64_t, kAlignSizes[7]> num7;
  EXPECT_TRUE(num7);
  CheckAlign(num7);
}

// Test AignedObjectPtr with a POD struct that does not have an
// integer-power-of-two size.
TEST_F(AlignedObjectPtrTest, StructAlign) {
  AlignedObjectPtr<TestStruct, kAlignSizes[0]> ts0;
  EXPECT_TRUE(ts0);
  CheckAlign(ts0);

  AlignedObjectPtr<TestStruct, kAlignSizes[1]> ts1;
  EXPECT_TRUE(ts1);
  CheckAlign(ts1);

  AlignedObjectPtr<TestStruct, kAlignSizes[2]> ts2;
  EXPECT_TRUE(ts2);
  CheckAlign(ts2);

  AlignedObjectPtr<TestStruct, kAlignSizes[3]> ts3;
  EXPECT_TRUE(ts3);
  CheckAlign(ts3);

  AlignedObjectPtr<TestStruct, kAlignSizes[4]> ts4;
  EXPECT_TRUE(ts4);
  CheckAlign(ts4);

  AlignedObjectPtr<TestStruct, kAlignSizes[5]> ts5;
  EXPECT_TRUE(ts5);
  CheckAlign(ts5);

  AlignedObjectPtr<TestStruct, kAlignSizes[6]> ts6;
  EXPECT_TRUE(ts6);
  CheckAlign(ts6);

  AlignedObjectPtr<TestStruct, kAlignSizes[7]> ts7;
  EXPECT_TRUE(ts7);
  CheckAlign(ts7);
}

// Test AignedObjectPtr with a complex container class that has a non-trivial
// constructor. The intent of this test is only to ensure that a non-trivial
// class can be embedded inside an AlignedObjectPtr. It is understood that
// only the memory allocated to the container itself will be aligned, and the
// individual objects stored within the container will not be aligned.
TEST_F(AlignedObjectPtrTest, ClassAlign) {
  TestStruct s1{1, 1}, s2{2, 2}, s3{3, 3};

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[0]>
      map0;
  EXPECT_TRUE(map0);
  EXPECT_TRUE(map0->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map0->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map0->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map0->emplace(std::string("s3"), s3).second);
  CheckAlign(map0);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[1]>
      map1;
  EXPECT_TRUE(map1);
  EXPECT_TRUE(map1->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map1->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map1->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map1->emplace(std::string("s3"), s3).second);
  CheckAlign(map1);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[2]>
      map2;
  EXPECT_TRUE(map2);
  EXPECT_TRUE(map2->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map2->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map2->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map2->emplace(std::string("s3"), s3).second);
  CheckAlign(map2);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[3]>
      map3;
  EXPECT_TRUE(map3);
  EXPECT_TRUE(map3->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map3->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map3->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map3->emplace(std::string("s3"), s3).second);
  CheckAlign(map3);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[4]>
      map4;
  EXPECT_TRUE(map4);
  EXPECT_TRUE(map4->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map4->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map4->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map4->emplace(std::string("s3"), s3).second);
  CheckAlign(map4);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[5]>
      map5;
  EXPECT_TRUE(map5);
  EXPECT_TRUE(map5->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map5->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map5->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map5->emplace(std::string("s3"), s3).second);
  CheckAlign(map5);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[6]>
      map6;
  EXPECT_TRUE(map6);
  EXPECT_TRUE(map6->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map6->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map6->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map6->emplace(std::string("s3"), s3).second);
  CheckAlign(map6);

  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[7]>
      map7;
  EXPECT_TRUE(map7);
  EXPECT_TRUE(map7->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map7->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map7->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map7->emplace(std::string("s3"), s3).second);
  CheckAlign(map7);
}

// Test the constructor-argument forwarding.
TEST_F(AlignedObjectPtrTest, ConstructorForward) {
  AlignedObjectPtr<TestClass, kAlignSizes[5]> tc0;
  EXPECT_TRUE(tc0);
  EXPECT_EQ(tc0->get_a(), 0);
  EXPECT_EQ(tc0->get_b(), 0);

  AlignedObjectPtr<TestClass, kAlignSizes[5]> tc1(0xACEDFACEULL, 0xDEADBEEF);
  EXPECT_TRUE(tc1);
  EXPECT_EQ(tc1->get_a(), 0xACEDFACEULL);
  EXPECT_EQ(tc1->get_b(), 0xDEADBEEF);
}

template <class T, size_t ALIGN>
void TestMoveAssign(AlignedObjectPtr<T, ALIGN> *t) {
  AlignedObjectPtr<T, ALIGN> tt;
  bool tb = static_cast<bool>(*t);
  tt = std::move(*t);
  EXPECT_EQ(static_cast<bool>(tt), tb);
}

// Test the move constructor and the move-assign operator.
TEST_F(AlignedObjectPtrTest, MoveAndAssign) {
  TestStruct s1{1, 1}, s2{2, 2}, s3{3, 3};
  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[5]>
      map;
  EXPECT_TRUE(map->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map->emplace(std::string("s3"), s3).second);
  TestMoveAssign(&map);
  EXPECT_FALSE(map);
}

// Returns the rvalue-reference of the object pointed to by |t|.
template <class T, size_t Align>
AlignedObjectPtr<T, Align> &&MoveObject(AlignedObjectPtr<T, Align> *t) {
  return std::move(*t);
}

// Test that self-move-assign works correctly.
TEST_F(AlignedObjectPtrTest, SelfMoveAssign) {
  TestStruct s1{1, 1}, s2{2, 2}, s3{3, 3};
  AlignedObjectPtr<absl::flat_hash_map<std::string, TestStruct>, kAlignSizes[5]>
      map;
  EXPECT_TRUE(map->emplace(std::string("s1"), s1).second);
  EXPECT_TRUE(map->emplace(std::string("s2"), s2).second);
  EXPECT_TRUE(map->emplace(std::string("s3"), s3).second);
  EXPECT_FALSE(map->emplace(std::string("s3"), s3).second);
  map = MoveObject(&map);
  EXPECT_TRUE(map);
  EXPECT_NE(map->find(std::string("s1")), map->end());
  EXPECT_NE(map->find(std::string("s2")), map->end());
  EXPECT_NE(map->find(std::string("s3")), map->end());
}

}  // namespace
}  // namespace asylo
