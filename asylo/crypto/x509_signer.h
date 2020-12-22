/*
 * Copyright 2020 Asylo authors
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
 */

#ifndef ASYLO_CRYPTO_X509_SIGNER_H_
#define ASYLO_CRYPTO_X509_SIGNER_H_

#include <openssl/base.h>

#include "asylo/util/status.h"

namespace asylo {

// Signs X509 Certificates.
class X509Signer {
 public:
  virtual ~X509Signer() = default;

  // Signs |x509|. Returns a non-OK Status if the signing operation failed. This
  // method treats |x509| as an in-out parameter.
  //
  virtual Status SignX509(X509 *x509) const = 0;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_X509_SIGNER_H_
