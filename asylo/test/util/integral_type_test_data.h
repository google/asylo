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

#ifndef ASYLO_TEST_UTIL_INTEGRAL_TYPE_TEST_DATA_H_
#define ASYLO_TEST_UTIL_INTEGRAL_TYPE_TEST_DATA_H_

#include <cstdint>
#include <limits>
#include <type_traits>

#include <gtest/gtest.h>

namespace asylo {
namespace internal {

// The implementation of IntegralTypeTestData. kIsSigned should be true if IntT
// is signed and false otherwise.
template <typename IntT, bool kIsSigned>
struct IntegralTypeTestDataImpl;

template <typename IntT>
struct IntegralTypeTestDataImpl<IntT, /*kIsSigned=*/true> {
  static constexpr IntT kValues[] = {std::numeric_limits<IntT>::min(),
                                     std::numeric_limits<IntT>::min() + 1,
                                     -1,
                                     0,
                                     1,
                                     std::numeric_limits<IntT>::max() - 1,
                                     std::numeric_limits<IntT>::max()};
};

template <typename IntT>
struct IntegralTypeTestDataImpl<IntT, /*kIsSigned=*/false> {
  static constexpr IntT kValues[] = {0, 1, std::numeric_limits<IntT>::max() - 1,
                                     std::numeric_limits<IntT>::max()};
};

template <typename IntT>
constexpr IntT IntegralTypeTestDataImpl<IntT, /*kIsSigned=*/true>::kValues[];

template <typename IntT>
constexpr IntT IntegralTypeTestDataImpl<IntT, /*kIsSigned=*/false>::kValues[];

}  // namespace internal

// Test data for testing conversions at the boundaries of an integral type. Each
// implementation has a static constexpr IntT kValues[] member consisting of
// test IntT values.
template <typename IntT>
using IntegralTypeTestData =
    internal::IntegralTypeTestDataImpl<IntT, std::is_signed<IntT>::value>;

// A testing::Types of frequently used integral types.
using IntegralTypes = ::testing::Types<
    char, unsigned char, signed char, short, unsigned short, int,
    unsigned int, long, unsigned long, long long, unsigned long long, size_t,
    ssize_t, int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
    uint64_t, intmax_t, uintmax_t>;

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_INTEGRAL_TYPE_TEST_DATA_H_
