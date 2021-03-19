/*
 * Copyright 2021 Asylo authors
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
 */

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERROR_MATCHERS_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERROR_MATCHERS_H_

#include "asylo/test/util/status_matchers.h"
#include "include/sgx_error.h"

namespace asylo {

// Matches a Status-like object that contains the given SGX error code.
PolymorphicStatusMatcherType SgxErrorIs(sgx_status_t sgx_status);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERROR_MATCHERS_H_
