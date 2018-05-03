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

#include <cpuid.h>

#include <gtest/gtest.h>

namespace {

class RdrandTest : public ::testing::Test {};

TEST_F(RdrandTest, HasRDRAND) {
  unsigned int eax, ebx, ecx, edx;

  __cpuid(0, eax, ebx, ecx, edx);
  // Bit 30 of ECX is set => machine supports RDRAND.
  EXPECT_TRUE(ecx & (1 << 30));
}

}  // namespace
