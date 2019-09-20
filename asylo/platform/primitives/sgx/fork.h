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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_FORK_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_FORK_H_

#include <sys/types.h>

namespace asylo {

int TakeSnapshot(char **output, size_t *output_len);

int Restore(const char *snapshot_layout, size_t snapshot_layout_len,
            char **output, size_t *output_len);

int TransferSecureSnapshotKey(const char *input, size_t input_len,
                              char **output, size_t *output_len);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_FORK_H_
