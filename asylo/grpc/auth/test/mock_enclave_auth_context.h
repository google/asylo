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

#ifndef ASYLO_GRPC_AUTH_TEST_MOCK_ENCLAVE_AUTH_CONTEXT_H_
#define ASYLO_GRPC_AUTH_TEST_MOCK_ENCLAVE_AUTH_CONTEXT_H_

#include <gmock/gmock.h>
#include "asylo/grpc/auth/enclave_auth_context.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {

class MockEnclaveAuthContext : public EnclaveAuthContext {
 public:
  MOCK_CONST_METHOD1(HasEnclaveIdentity,
                     bool(const EnclaveIdentityDescription &description));

  MOCK_CONST_METHOD1(FindEnclaveIdentity,
                     StatusOr<const EnclaveIdentity *>(
                         const EnclaveIdentityDescription &description));

  MOCK_CONST_METHOD1(EvaluateAcl,
                     StatusOr<bool>(const IdentityAclPredicate &acl));

  MOCK_CONST_METHOD1(
      EvaluateAcl,
      StatusOr<bool>(const EnclaveIdentityExpectation &expectation));
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_TEST_MOCK_ENCLAVE_AUTH_CONTEXT_H_
