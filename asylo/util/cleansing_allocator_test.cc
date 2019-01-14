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

#include "asylo/util/cleansing_allocator.h"

#include <cstdlib>
#include <iostream>
#include <list>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"

namespace asylo {
namespace {

const size_t kNumIterations = 1000;

// TestAllocator is a derived type of std::allocator, and overrides its
// deallocate method. The overridden deallocate method verifies that the memory
// being deallocated has been cleansed (i.e., zeroed out) before calling the
// deallocate method of the base class.
//
// The tests in this file use the TestAllocator as the template parameter |A|
// for the CleansingAllocator. Such a setup verifies that the
// CleansingAllocator is indeed cleaning up the memory before calling
// the deallocate method of |A|.
template <typename T>
class TestAllocator : public std::allocator<T> {
 public:
  TestAllocator() = default;
  template <typename U>
  explicit TestAllocator(const TestAllocator<U> &a)
      : std::allocator<T>::allocator(a) {}
  ~TestAllocator() = default;
  template <typename U>
  struct rebind {
    using other = TestAllocator<U>;
  };
  void deallocate(typename std::allocator<T>::pointer ptr,
                  typename std::allocator<T>::size_type n) {
    uint8_t *buffer = reinterpret_cast<uint8_t *>(ptr);
    for (int i = 0; i < n * sizeof(T); i++) {
      ASSERT_EQ(buffer[i], 0);
    }
    std::allocator_traits<std::allocator<T>>::deallocate(*this, ptr, n);
  }
};

template <typename T, typename U>
bool operator==(const TestAllocator<T> &lhs, const TestAllocator<U> &rhs) {
  return true;
}

template <typename T, typename U>
bool operator!=(const TestAllocator<T> &lhs, const TestAllocator<U> &rhs) {
  return !(lhs == rhs);
}

// A typed test fixture is used for tests that require a single type object.
template <typename T>
class TypedCleansingAllocatorTest : public ::testing::Test {};

// Test the allocator with objects of varying types/sizes. The sizes of the
// objects are somewhat arbitrarily chosen.
typedef ::testing::Types<SafeBytes<8>, UnsafeBytes<15>, SafeBytes<235>,
                         UnsafeBytes<519>, uint8_t, uint16_t, uint32_t,
                         uint64_t>
    MyTypes;
TYPED_TEST_SUITE(TypedCleansingAllocatorTest, MyTypes);

TYPED_TEST(TypedCleansingAllocatorTest, VectorTest) {
  using TestVector =
      std::vector<TypeParam,
                  CleansingAllocator<TypeParam, TestAllocator<TypeParam>>>;
  std::unique_ptr<TestVector> v(new TestVector);

  for (int i = 0; i < kNumIterations; i++) {
    v->push_back(TrivialRandomObject<TypeParam>());
  }

  // Resetting v will free up all the allocated memory, and make sure that
  // the cleansing was performed correctly.
  v.reset(nullptr);
}

// std::list utilizes the rebind functionality of the allocator, and
// consequently, in addition to testing the allocator with std::vector,
// it is also tested with std::list.
TYPED_TEST(TypedCleansingAllocatorTest, ListTest) {
  using TestList =
      std::list<TypeParam,
                CleansingAllocator<TypeParam, TestAllocator<TypeParam>>>;
  std::unique_ptr<TestList> l(new TestList);

  for (int i = 0; i < kNumIterations; i++) {
    l->push_back(TrivialRandomObject<TypeParam>());
  }

  // Resetting l will free up all the allocated memory, and make sure that
  // the cleansing was performed correctly.
  l.reset(nullptr);
}

// std::basic_string is another commonly-used type for storing secrets,
// and consequently, the following test explicitly tests the functioning
// of this type with the cleansing allocator.
TYPED_TEST(TypedCleansingAllocatorTest, StringTest) {
  using CleansingString =
      std::basic_string<uint8_t, std::char_traits<uint8_t>,
                        CleansingAllocator<uint8_t, TestAllocator<uint8_t>>>;
  using TestList = std::list<
      CleansingString,
      CleansingAllocator<CleansingString, TestAllocator<CleansingString>>>;
  std::unique_ptr<TestList> l(new TestList);

  for (int i = 0; i < kNumIterations; i++) {
    TypeParam obj = TrivialRandomObject<TypeParam>();
    l->push_back(
        CleansingString(reinterpret_cast<uint8_t *>(&obj), sizeof(obj)));
  }

  // Resetting l will free up all the allocated memory, and make sure that
  // the cleansing was performed correctly.
  l.reset(nullptr);
}

}  // namespace
}  // namespace asylo
