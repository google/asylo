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

#include "asylo/grpc/auth/util/safe_string.h"
#include "include/grpc/support/alloc.h"

void safe_string_init(safe_string *safe_str) {
  safe_str->data = nullptr;
  safe_str->size = 0;
}

void safe_string_assign(safe_string *safe_str, size_t size, const char *data) {
  /* Do not attempt to reuse already allocated memory. */
  safe_string_free(safe_str);
  safe_str->data = static_cast<char *>(gpr_malloc(size));
  if (size > 0) {
    /* Non-null std::string. */
    memcpy(safe_str->data, data, size);
  }
  safe_str->size = size;
}

void safe_string_copy(safe_string *dest, const safe_string *src) {
  safe_string_assign(dest, src->size, src->data);
}

void safe_string_free(safe_string *safe_str) {
  if (safe_str->size != 0) {
    gpr_free(safe_str->data);

    /* Reset the state. */
    safe_str->data = nullptr;
    safe_str->size = 0;
  }
}
