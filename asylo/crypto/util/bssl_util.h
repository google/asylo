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

#ifndef ASYLO_CRYPTO_UTIL_BSSL_UTIL_H_
#define ASYLO_CRYPTO_UTIL_BSSL_UTIL_H_

#include <openssl/err.h>
#include <string>

namespace asylo {

// Returns a string description of the last error encountered by BoringSSL.
std::string BsslLastErrorString();

}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BSSL_UTIL_H_
