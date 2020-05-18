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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SGX_IDENTITY_TEST_UTIL_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SGX_IDENTITY_TEST_UTIL_H_

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

// Generates a valid CodeIdentity according to the constraints defined by the
// inputs. |mrenclave_constraint| provides the constraints on whether mrenclave
// should be set. If |mrenclave_constraint| is {false}, then mrenclave is not
// set. If |mrenclave_constraint| is {true}, then mrenclave is set. If
// |mrenclave_constraint| is {true, false} mrenclave is either set or not set
// with equal probability. |mrsigner_constraint| controls setting of mrsigner in
// a similar fashion.
CodeIdentity GetRandomValidCodeIdentityWithConstraints(
    const std::vector<bool> &mrenclave_constraint,
    const std::vector<bool> &mrsigner_constraint);

// Generates a valid CodeIdentity without any constraints.
CodeIdentity GetRandomValidCodeIdentity();

// Generates a valid CodeIdentityMatchSpec. A valid match spec must have all its
// fields set.
CodeIdentityMatchSpec GetRandomValidMatchSpec();

// Generates a valid SgxIdentity according to the constraints defined by the
// inputs, in a similar vein as GetRandomValidCodeIdentityWithConstraints.
SgxIdentity GetRandomValidSgxIdentityWithConstraints(
    const std::vector<bool> &mrenclave_constraint,
    const std::vector<bool> &mrsigner_constraint,
    const std::vector<bool> &cpu_svn_constraint,
    const std::vector<bool> &sgx_type_constraint);

SgxIdentity GetRandomValidSgxIdentity();

SgxIdentityMatchSpec GetRandomValidSgxMatchSpec();

SgxIdentityExpectation GetRandomValidSgxExpectation();

// Sets |generic_identity| to a randomly-initialized valid EnclaveIdentity,
// where the |identity| is a serialized SgxIdentity. Also writes the underlying
// SGX identity to |corresponding_sgx_identity|.
Status SetRandomValidGenericIdentity(EnclaveIdentity *generic_identity,
                                     SgxIdentity *corresponding_sgx_identity);

// Sets |generic_identity| to a randomly-initialized invalid EnclaveIdentity,
// where the serialized identity is an SgxIdentity.
Status SetRandomInvalidGenericIdentity(EnclaveIdentity *generic_identity);

// Sets |generic_spec| to a randomly-initialized string that corresponds to a
// valid SGX match spec. Also writes the underlying SGX match spec to
// |corresponding_sgx_spec|.
Status SetRandomValidGenericMatchSpec(
    std::string *generic_spec, SgxIdentityMatchSpec *corresponding_sgx_spec);

// Sets |generic_spec| to a randomly-initialized string that corresponds to an
// invalid SGX match spec.
Status SetRandomInvalidGenericMatchSpec(std::string *generic_spec);

// Sets |generic_expectation| to a randomly-initialized valid
// EnclaveIdentityExpectation. Also writes the underlying SGX expectation to
// |corresponding_sgx_expectation|.
Status SetRandomValidGenericExpectation(
    EnclaveIdentityExpectation *generic_expectation,
    SgxIdentityExpectation *corresponding_sgx_expectation);

// Sets |generic_expectation| to a randomly-initialized invalid
// EnclaveIdentityExpectation.
Status SetRandomInvalidGenericExpectation(
    EnclaveIdentityExpectation *generic_expectation);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SGX_IDENTITY_TEST_UTIL_H_
