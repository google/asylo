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

#ifndef ASYLO_PLATFORM_CORE_SHARED_NAME_KIND_H_
#define ASYLO_PLATFORM_CORE_SHARED_NAME_KIND_H_

#ifdef __cplusplus
extern "C" {
#endif

/// Separate namespaces for naming shared resources across the enclave boundary.
enum SharedNameKind {
  /// A default provided for resources that don't belong to any particular
  /// namespace.
  kUnspecifiedName = 0,

  /// An address resource.
  kAddressName,

  /// A socket resource.
  kSocketName,

  /// A timer resource.
  kTimerName,

  /// A shared memory block.
  kMemBlockName,
};

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_CORE_SHARED_NAME_KIND_H_
