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

#include "asylo/util/status_helpers.h"

#include "asylo/util/status.h"
#include "asylo/util/status.pb.h"

namespace asylo {

StatusProto StatusToProto(const Status &status) {
  StatusProto status_proto;
  status.SaveTo(&status_proto);
  return status_proto;
}

Status StatusFromProto(const StatusProto &status_proto) {
  Status status;
  status.RestoreFrom(status_proto);
  return status;
}

}  // namespace asylo
