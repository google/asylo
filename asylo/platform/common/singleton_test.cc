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

#include "asylo/platform/common/singleton.h"

#include <openssl/mem.h>
#include <openssl/rand.h>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

namespace asylo {
namespace {

constexpr size_t kBufSize = 1024;
constexpr size_t kLoopCount = 1024 * 128;
constexpr size_t kNumThreads = 8;

// NumericConstant template class defines a unique C++ type for each value of
// template parameter |N|.
template <int N>
struct NumericConstant {
  NumericConstant() : value{N} {
    std::thread::id thread_id = std::this_thread::get_id();
    std::hash<std::thread::id> hasher;
    tid_hash = hasher(thread_id);
  }
  const int value;
  size_t tid_hash;
};

// LethargicFactory takes a very long time to construct an instance of template
// parameter |T|.
template <typename T>
struct LethargicFactory {
  using value_type = T;
  static T *Construct() {
    uint8_t buffer[kBufSize];
    for (int i = 0; i < kLoopCount; i++) {
      RAND_bytes(buffer, kBufSize);
      OPENSSL_cleanse(buffer, kBufSize);
    }
    return new T();
  }
};

// Thread routine that is launched from the SingletonCorrectness test. It
// obtains an instance of |T| via the Singleton template class and takes one
// of the following two actions:
//   1. If *|ptr| is nullptr, it sets *|ptr| to the instance address.
//   2. If *|ptr| is not nullptr, it verifies that the instance address that
//      it got is the same as the address held by *|ptr|.
template <typename T>
void TestSingleton(T **ptr, absl::Mutex *mu) {
  T *tmp_ptr = Singleton<T, LethargicFactory<T>>::get();

  absl::MutexLock lock(mu);
  if (*ptr == nullptr) {
    *ptr = tmp_ptr;
    return;
  }

  ASSERT_EQ(*ptr, tmp_ptr);
}

// A typed test fixture is used for tests that require a single type object.
template <typename T>
class TypedSingletonTest : public ::testing::Test {};

typedef ::testing::Types<NumericConstant<0>,
                         absl::flat_hash_map<std::string, std::string>,
                         std::string, std::vector<uint8_t>>
    MyTypes;

TYPED_TEST_SUITE(TypedSingletonTest, MyTypes);

// Launches eight threads and invokes Singleton<TypeParam>::get() from each
// thread. If Singleton is working correctly, all threads must get the same
// pointer back.
TYPED_TEST(TypedSingletonTest, SingletonCorrectness) {
  TypeParam *ptr = nullptr;
  absl::Mutex mu;
  std::vector<std::thread> threads;

  for (int i = 0; i < kNumThreads; i++) {
    threads.emplace_back(TestSingleton<TypeParam>, &ptr, &mu);
  }

  for (auto &thread : threads) {
    thread.join();
  }

  EXPECT_NE(ptr, nullptr);

  Singleton<TypeParam>::Destruct();
  EXPECT_EQ(Singleton<TypeParam>::get(), nullptr);
}

}  // namespace
}  // namespace asylo
