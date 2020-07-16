/*
 *
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
 *
 */

#include "asylo/identity/attestation/sgx/internal/intel_certs/qe_identity.h"

namespace asylo {
namespace sgx {

const char *const kIntelEcdsaQeIdentityTextproto = R"pb(
  code_identity {
    mrenclave {
      hash: "\315\312\337\267\333\"\255\245\375`4U\315\341\277\237\242X\372_(M\315n\014c9/c:\021\005"
    }
    signer_assigned_identity {
      mrsigner {
        hash: "\214OWu\327\226P>\226\023\177w\306\212\202\232\000V\254\215\355p\024\013\010\033\tD\220\305{\377"
      }
      isvprodid: 1
      isvsvn: 5
    }
    miscselect: 0
    attributes { flags: 21 xfrm: 7 }
  }
  machine_configuration: {
    cpu_svn: {
      # No expectation on CPUSVN
      value: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    }
    sgx_type: STANDARD
  }
)pb";

}  // namespace sgx
}  // namespace asylo
