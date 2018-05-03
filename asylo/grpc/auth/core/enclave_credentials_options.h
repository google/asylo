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

#ifndef ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_OPTIONS_H_
#define ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_OPTIONS_H_

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/util/safe_string.h"

typedef struct {
  safe_string additional_authenticated_data;

  /* The credential holder's offered assertions. */
  assertion_description_array self_assertions;

  /* The credential holder's accepted peer assertions. */
  assertion_description_array accepted_peer_assertions;

} grpc_enclave_credentials_options;

/* Initializes an options object. This should be called before assigning to or
 * accessing any of the members. */
void grpc_enclave_credentials_options_init(
    grpc_enclave_credentials_options *options);

/* Destroys the contents of an options object. */
void grpc_enclave_credentials_options_destroy(
    grpc_enclave_credentials_options *options);

#endif  // ASYLO_GRPC_AUTH_CORE_ENCLAVE_CREDENTIALS_OPTIONS_H_
