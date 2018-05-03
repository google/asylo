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

#ifndef ASYLO_PLATFORM_COMMON_HASH_COMBINE_H_
#define ASYLO_PLATFORM_COMMON_HASH_COMBINE_H_

#include <functional>

namespace asylo {

// Combines a seed value (likely another hash) with the hash of a given value.
template <typename T>
size_t HashCombine(size_t seed, const T &value) {
  size_t hash = std::hash<T>()(value);
  // 2^64 / Phi = 0x9e3779b97f4a7c16 for "random" bit-flips.
  // Phi is a well-known irrational number (1 + sqrt(5))/2
  // Shifting is added in order to spread bits around for greater diversity.
  return seed ^ (hash + 0x9e3779b97f4a7c16 + (seed << 12) + (seed >> 4));
}

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_HASH_COMBINE_H_
