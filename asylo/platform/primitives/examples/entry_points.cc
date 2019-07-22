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

#include <unistd.h>


namespace asylo {

extern "C" {

int __asylo_handle_signal(const char *input, size_t input_len) {
  return 0;
}


int __asylo_take_snapshot(char **output, size_t *output_len) {
  return 0;
}


int __asylo_restore(const char *snapshot_layout, size_t snapshot_layout_len,
                    char **output, size_t *output_len) {
  return 0;
}


int __asylo_transfer_secure_snapshot_key(const char *input, size_t input_len,
                                         char **output, size_t *output_len) {
  return 0;
}

}  // extern "C"

}  // namespace asylo
