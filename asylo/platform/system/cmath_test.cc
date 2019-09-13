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

#include <cmath>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"

namespace {

using ::testing::Eq;

TEST(CmathTest, LongDoubleFunctions) {
  long double long_doubles[] = {
    std::hypotl(1.0, 2.0),
    std::sqrtl(1.0),
  };
  EXPECT_THAT(ABSL_ARRAYSIZE(long_doubles), Eq(2));
}

TEST(CmathTest, Tr1DoubleFunctions) {
  int quo;
  double doubles[] = {
    std::acosh(1.0),
    std::asinh(1.0),
    std::atanh(1.0),
    std::cbrt(1.0),
    std::copysign(1.0, 2.0),
    std::erf(1.0),
    std::erfc(1.0),
    std::exp2(1.0),
    std::expm1(1.0),
    std::fdim(1.0, 2.0),
    std::fma(1.0, 2.0, 3.0),
    std::fmax(1.0, 2.0),
    std::fmin(1.0, 2.0),
    std::hypot(1.0, 2.0),
    static_cast<double>(std::ilogb(1.0)),
    std::lgamma(1.0),
    std::log1p(1.0),
    std::log2(1.0),
    std::logb(1.0),
    std::nan("NAN"),
    std::nearbyint(0.0),
    std::nextafter(1.0, HUGE_VAL),
    std::remainder(1.0, 2.0),
    std::remquo(1.0, 1.0, &quo),
    std::rint(1.0),
    std::round(1.0),
    std::scalbln(1.0, 3),
    std::scalbn(1.0, 3),
    std::tgamma(1.0),
    std::trunc(1.0),
  };
  long int lvalues[] = {
    std::lrint(1.0),
    std::lround(1.0),
  };
  long long int llvalues[] = {
    std::llrint(1.0),
    std::llround(1.0),
  };
  EXPECT_THAT(ABSL_ARRAYSIZE(doubles), Eq(30));
  EXPECT_THAT(ABSL_ARRAYSIZE(lvalues), Eq(2));
  EXPECT_THAT(ABSL_ARRAYSIZE(llvalues), Eq(2));
}

TEST(CmathTest, Tr1FloatFunctions) {
  int quo;
  float floats[] = {
    std::acoshf(1.0f),
    std::asinhf(1.0f),
    std::atanhf(1.0f),
    std::cbrtf(1.0f),
    std::copysignf(1.0f, 2.0f),
    std::erff(1.0f),
    std::erfcf(1.0f),
    std::exp2f(1.0f),
    std::expm1f(1.0f),
    std::fdimf(1.0f, 2.0f),
    std::fmaf(1.0f, 2.0f, 3.0f),
    std::fmaxf(1.0f, 2.0f),
    std::fminf(1.0f, 2.0f),
    std::hypotf(1.0f, 2.0f),
    static_cast<float>(std::ilogbf(1.0f)),
    std::lgammaf(1.0f),
    std::log1pf(1.0f),
    std::log2f(1.0f),
    std::logbf(1.0f),
    std::nanf("NAN"),
    std::nearbyintf(0.2f),
    std::nextafterf(1.0f, HUGE_VALF),
    std::remainderf(1.0f, 2.0f),
    std::remquof(1.0f, 1.0f, &quo),
    std::rintf(1.0f),
    std::roundf(1.0f),
    std::scalblnf(1.0f, 3),
    std::scalbnf(1.0f, 3),
    std::tgammaf(1.0f),
    std::truncf(1.0f),
  };
  long int lvalues[] = {
    std::lrintf(1.0f),
    std::lroundf(1.0f),
  };
  long long int llvalues[] = {
    std::llrintf(1.0f),
    std::llroundf(1.0f),
  };
  EXPECT_THAT(ABSL_ARRAYSIZE(floats), Eq(30));
  EXPECT_THAT(ABSL_ARRAYSIZE(lvalues), Eq(2));
  EXPECT_THAT(ABSL_ARRAYSIZE(llvalues), Eq(2));
}

}  // namespace
