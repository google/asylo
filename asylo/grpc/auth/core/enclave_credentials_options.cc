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

#include "asylo/grpc/auth/core/enclave_credentials_options.h"

void grpc_enclave_credentials_options_init(
    grpc_enclave_credentials_options *options) {
  safe_string_init(&options->additional_authenticated_data);
  assertion_description_array_init(/*count=*/0, &options->self_assertions);
  assertion_description_array_init(/*count=*/0,
                                   &options->accepted_peer_assertions);
}

void grpc_enclave_credentials_options_destroy(
    grpc_enclave_credentials_options *options) {
  safe_string_free(&options->additional_authenticated_data);
  assertion_description_array_free(&options->self_assertions);
  assertion_description_array_free(&options->accepted_peer_assertions);
}
