/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_UTIL_ASYLO_MACROS_H_
#define ASYLO_UTIL_ASYLO_MACROS_H_

// This header file defines a number of utility macros that Asylo components
// may rely on. This is provided as an alternative to depending on ABSL.

// A portable alternative to __attribute__((warn_unused_result)).
#if (defined(__clang__) || defined(__GNUC__)) && !defined(ASYLO_MUST_USE_RESULT)
#define ASYLO_MUST_USE_RESULT __attribute__((warn_unused_result))
#else
#define ASYLO_MUST_USE_RESULT
#endif

#endif  // ASYLO_UTIL_ASYLO_MACROS_H_
