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

#ifndef ASYLO_GRPC_AUTH_UTIL_SAFE_STRING_H_
#define ASYLO_GRPC_AUTH_UTIL_SAFE_STRING_H_

#include <string.h>

/* safe_string is a container for a fixed-length std::string. A safe_string either
 * represents some non-zero length std::string or the null std::string, in which case it
 * is zero-length and has a NULL data member. A safe_string will take on the
 * value of the null std::string when it is newly-initialized or freed.
 *
 * safe_string is not intended to be a general-purpose std::string utility. It simply
 * provides convenience functions for safely creating copies of strings, and
 * managing allocated buffers using gRPC memory management utilities.
 *
 * safe_string is not efficient in terms of memory reuse. As a result, repeated
 * assign and copy operations are not efficient.
 *
 * safe_string_init must be called on a safe_string object before calling any
 * other function.
 *
 * A safe_string can be safely assigned to using safe_string_assign.
 *
 * A safe_string can be safely copied to another safe_string using
 * safe_string_copy.
 *
 * A safe_string should be destroyed with safe_string_free. */
typedef struct {
  char *data;
  size_t size;
} safe_string;

/* Constructor for safe_string. Sets |safe_str| to the null std::string. This must be
 * called before calling any other functions on |safe_str|. */
void safe_string_init(safe_string *safe_str);

/* Sets |safe_str| to contain the first |size| bytes from |data|. If |size| is
 * non-zero, then the caller must provide |data| containing |size| bytes.  If
 * |size| is zero, then the resulting safe_string will be null. The contents of
 * |dest| will be freed prior to being overwritten. */
void safe_string_assign(safe_string *safe_str, size_t size, const char *data);

/* Makes a copy of |src| and places the result in |dest|. The contents of |dest|
 * will be freed prior to being overwritten. */
void safe_string_copy(safe_string *dest, const safe_string *src);

/* Destroys the contents of |safe_str|. */
void safe_string_free(safe_string *safe_str);

#endif  // ASYLO_GRPC_AUTH_UTIL_SAFE_STRING_H_
