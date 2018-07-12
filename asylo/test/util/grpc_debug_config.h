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

#ifndef ASYLO_TEST_UTIL_GRPC_DEBUG_CONFIG_H_
#define ASYLO_TEST_UTIL_GRPC_DEBUG_CONFIG_H_

#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"

namespace asylo {

// Updates |config| to set GRPC_TRACE to |trace_level| inside the enclave.
//
// See gRPC's documentation for environment variables for all possible values of
// GRPC_TRACE:
//
// https://github.com/grpc/grpc/blob/master/doc/environment_variables.md
void SetEnclaveGrpcTrace(absl::string_view trace_level, EnclaveConfig *config);

// Updates |config| to set GRPC_VERBOSITY to |verbosity_level| inside the
// enclave.
//
// See gRPC's documentation for environment variables for all possible values of
// GRPC_VERBOSITY:
//
// https://github.com/grpc/grpc/blob/master/doc/environment_variables.md
void SetEnclaveGrpcVerbosity(absl::string_view verbosity_level,
                             EnclaveConfig *config);

// Sets GRPC_VERBOSITY to "debug" and GRPC_TRACE to "all" in the given |config|
// to enable the most verbose gRPC trace and logging.
void SetEnclaveGrpcDebugConfig(EnclaveConfig *config);

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_GRPC_DEBUG_CONFIG_H_
