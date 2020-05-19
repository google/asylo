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
  code_identity: {
    mrenclave: {
      hash: "\x50\x58\xd2\x50\x86\x6b\x37\x00\x23\x00\xea\x13\xdc\xb9\x00\xcb\xe4\xbc\x1c\x88\xc2\x6f\xb5\x74\x1b\x47\xfe\xb8\xb5\xcc\x6f\xbc\x23\x5c\xa6\x3d\x8d\x22\xe7\x70\xb1\x6e\x26\xf2\x9c\x23\x01\xf2\x0b\x2b\x2f\x3d\x85\xc4\x88\x1d\x62\x38\xaf\x1b\x03\x43\xd6\xef"
    }
    signer_assigned_identity: {
      mrsigner: {
        hash: "\x8c\x4f\x57\x75\xd7\x96\x50\x3e\x96\x13\x7f\x77\xc6\x8a\x82\x9a\x00\x56\xac\x8d\xed\x70\x14\x0b\x08\x1b\x09\x44\x90\xc5\x7b\xff"
      }
      isvprodid: 1
      isvsvn: 5
    }
    miscselect: 0
    attributes: { flags: 0x1100000000000000 xfrm: 0x0 }
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
