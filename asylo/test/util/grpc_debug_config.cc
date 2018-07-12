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

#include "asylo/test/util/grpc_debug_config.h"

namespace asylo {

void SetEnclaveGrpcTrace(absl::string_view trace_level,
                         EnclaveConfig *config) {
  EnvironmentVariable *trace = config->add_environment_variables();
  trace->set_name("GRPC_TRACE");
  trace->set_value(trace_level);
}

void SetEnclaveGrpcVerbosity(absl::string_view verbosity_level,
                             EnclaveConfig *config) {
  EnvironmentVariable *verbosity = config->add_environment_variables();
  verbosity->set_name("GRPC_VERBOSITY");
  verbosity->set_value(verbosity_level);
}

void SetEnclaveGrpcDebugConfig(EnclaveConfig *config) {
  SetEnclaveGrpcTrace("all", config);
  SetEnclaveGrpcVerbosity("debug", config);
}

}  // namespace asylo
