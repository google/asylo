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

#include "asylo/grpc/auth/core/assertion_description.h"

#include "include/grpc/support/alloc.h"


/* Assertion description. */

void assertion_description_init(assertion_description *desc) {
  /* The identity_type field takes on a value from the EnclaveIdentityType
   * proto2 enum. The default value of a proto2 enum is 0, which indicates the
   * UNKNOWN identity type for the EnclaveIdentityType enum. As this value
   * should never be used to describe an actual assertion, it is an appropriate
   * value for a newly-initialized assertion_description. This is the invariant
   * maintained for an empty description. When the structure is freed, the
   * identity_type field will also be reset to this value. */
  desc->identity_type = 0;
  safe_string_init(&desc->authority_type);
}

void assertion_description_assign(int32_t identity_type,
                                  const char *authority_type,
                                  size_t authority_type_size,
                                  assertion_description *desc) {
  desc->identity_type = identity_type;
  safe_string_assign(&desc->authority_type, authority_type_size,
                     authority_type);
}

void assertion_description_copy(const assertion_description *src,
                                assertion_description *dest) {
  dest->identity_type = src->identity_type;
  safe_string_copy(/*dest=*/&dest->authority_type,
                   /*src=*/&src->authority_type);
}

void assertion_description_free(assertion_description *desc) {
  if (desc != nullptr) {
    safe_string_free(&desc->authority_type);
    desc->identity_type = 0;
  }
}

/* Assertion description array. */

void assertion_description_array_init(size_t count,
                                      assertion_description_array *array) {
  /* If |count| is 0, then the call to gpr_malloc will return nullptr. This is
   * the invariant maintained for an empty array. When the structure is freed,
   * the array's capacity will be reset to 0 and its descriptions pointer will
   * be reset to nullptr. */
  array->count = count;
  array->descriptions = static_cast<assertion_description *>(
      gpr_malloc(count * sizeof(*array->descriptions)));
  size_t i;
  for (i = 0; i < array->count; ++i) {
    assertion_description_init(&array->descriptions[i]);
  }
}

bool assertion_description_array_assign_at(size_t index, int32_t identity_type,
                                           const char *authority_type,
                                           size_t authority_type_size,
                                           assertion_description_array *array) {
  if (index >= array->count) {
    return false;
  }

  assertion_description_assign(identity_type, authority_type,
                               authority_type_size,
                               &array->descriptions[index]);
  return true;
}

void assertion_description_array_copy(const assertion_description_array *src,
                                      assertion_description_array *dest) {
  assertion_description_array_free(dest);
  assertion_description_array_init(src->count, dest);
  size_t i;
  for (i = 0; i < src->count; ++i) {
    assertion_description_copy(&src->descriptions[i], &dest->descriptions[i]);
  }
}

void assertion_description_array_free(assertion_description_array *array) {
  if ((array == nullptr) || (array->descriptions == nullptr) ||
      (array->count == 0)) {
    return;
  }

  size_t i;
  for (i = 0; i < array->count; ++i) {
    assertion_description_free(&array->descriptions[i]);
  }
  gpr_free(array->descriptions);

  /* Reset the array state. */
  array->descriptions = nullptr;
  array->count = 0;
}
