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

#ifndef ASYLO_PLATFORM_POSIX_PTHREAD_IMPL_H_
#define ASYLO_PLATFORM_POSIX_PTHREAD_IMPL_H_

#include <pthread.h>

namespace asylo {
namespace pthread_impl {

// Returns the thread ID of the first thread in |list|.
pthread_t pthread_list_first(const __pthread_list_t &list);

// Adds |thread_id| as the last entry of |list|.
void pthread_list_insert_last(__pthread_list_t *list, pthread_t thread_id);

// Removes the first entry of |list|.
void pthread_list_remove_first(__pthread_list_t *list);

// Returns true if |list| contains |thread_id|; false otherwise.
bool pthread_list_contains(const __pthread_list_t &list, pthread_t thread_id);

}  // namespace pthread_impl
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_PTHREAD_IMPL_H_
