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

#ifndef ASYLO_GRPC_AUTH_TEST_END2END_TEST_UTIL_H_
#define ASYLO_GRPC_AUTH_TEST_END2END_TEST_UTIL_H_

#include "asylo/grpc/auth/core/assertion_description.h"

// Sets |description| to describe a null assertion--an assertion that asserts
// the null enclave identity.
//
// This function is provided for use in test code that deals with gRPC auth at
// the C level. Normally, enclave identities should only be configured in the
// C++ layer.
void set_null_assertion(assertion_description *description);

#endif  // ASYLO_GRPC_AUTH_TEST_END2END_TEST_UTIL_H_
