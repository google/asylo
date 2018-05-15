/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_REGISTER_SIGNAL_H_
#define ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_REGISTER_SIGNAL_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Calls enc_untrusted_register_handler to register a signal handler on the
// host.
int enc_register_signal(int signum, const char *enclave_name, size_t len);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_REGISTER_SIGNAL_H_
