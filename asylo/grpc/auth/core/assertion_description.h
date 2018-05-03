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

#ifndef ASYLO_GRPC_AUTH_CORE_ASSERTION_DESCRIPTION_H_
#define ASYLO_GRPC_AUTH_CORE_ASSERTION_DESCRIPTION_H_

#include <stdint.h>
#include <stdlib.h>

#include "asylo/grpc/auth/util/safe_string.h"

/* Assertion description. */

/* This structure corresponds to the AssertionDescription proto defined in
 * asylo/identity/identity.proto. */
typedef struct {
  /* Corresponds to AssertionDescription.identity_type. */
  int32_t identity_type;

  /* Corresponds to AssertionDescription.authority_type. */
  safe_string authority_type;
} assertion_description;

/* Constructor for assertion_description. This must be called before calling any
 * other functions on |desc|. */
void assertion_description_init(assertion_description *desc);

/* Sets |desc| to an assertion description having identity type |identity_type|
 * and authority type |authority_type|. |authority_type_size| is the length of
 * |authority_type|. */
void assertion_description_assign(int32_t identity_type,
                                  const char *authority_type,
                                  size_t authority_type_size,
                                  assertion_description *desc);

/* Makes a deep copy of |src| and places the result in |dest|. Frees any
 * existing description in |dest|. */
void assertion_description_copy(const assertion_description *src,
                                assertion_description *dest);

/* Destroys the contents of |desc|. */
void assertion_description_free(assertion_description *desc);

/* Assertion description array. */

/* A container for assertion_descriptions, where |descriptions| is an array of
 * |count| assertion descriptions. */
typedef struct {
  assertion_description *descriptions;
  size_t count;
} assertion_description_array;

/* Constructor for assertion_description_array. Sets |array| to a capacity of
 * |count|. This must be called before calling any other functions on |array|.
 */
void assertion_description_array_init(size_t count,
                                      assertion_description_array *array);

/* Sets the description at index |index| in |array| to contain |identity_type|
 * and |authority_type| if |index| is a valid index in the array. Returns false
 * if |index| is not a valid index in the array. */
bool assertion_description_array_assign_at(size_t index, int32_t identity_type,
                                           const char *authority_type,
                                           size_t authority_type_size,
                                           assertion_description_array *array);

/* Makes a deep copy of |src| and places the result in |dest|. Frees any
 * existing descriptions in |dest|. */
void assertion_description_array_copy(const assertion_description_array *src,
                                      assertion_description_array *dest);

/* Destroys the contents of |array|. */
void assertion_description_array_free(assertion_description_array *array);

#endif  // ASYLO_GRPC_AUTH_CORE_ASSERTION_DESCRIPTION_H_
