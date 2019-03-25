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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_DLFCN_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_DLFCN_H_

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_LOCAL 0

#define RTLD_NOW 2

void *dlopen(const char *filename, int flags);
void *dlsym(void *handle, const char *symbol);
int dlclose(void *handle);
char *dlerror();

#ifdef __cplusplus
}
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_DLFCN_H_
