/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_OPENCENSUS_CLIENT_CONFIG_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_OPENCENSUS_CLIENT_CONFIG_H_

#include <string>

#include "absl/strings/string_view.h"
#include "absl/time/time.h"

struct OpenCensusClientConfig {
  absl::Duration granularity;
  std::string view_name_root;
};

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_CLIENTS_OPENCENSUS_CLIENT_CONFIG_H_
