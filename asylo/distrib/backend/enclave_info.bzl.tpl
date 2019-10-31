#
# Copyright 2018 Asylo authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Starlark support for Asylo backends."""

# This provider is accessible to all enclave backends to label their targets as
# enclaves specifically. The enclave_binary and enclave_test macros then use
# this information to understand data dependencies and generate command-line
# arguments to automatically send to the program.
EnclaveInfo = provider()

# Each backend defines a rule that defines itself as an Asylo backend label.
# The provider is used by backend transition rules to do a couple things:
#
#   1. Ensure the passed label is the right type (declared to be a backend).
#   2. Copy important providers through the transition, such as CcInfo, the
#      fact that the target is an enclave (i.e., EnclaveInfo), and which
#      kind of enclave it is (e.g., SGXEnclaveInfo). Each enclave backend has
#      its own rules for defining and using an enclave target, so those
#      providers need to be present for those rules to work correctly.
AsyloBackendInfo = provider(
    doc = "Provided by all Asylo backends." +
          " The forward_providers field is a list of all providers that enclave" +
          " binaries should forward through a transition." +
          " Both EnclaveInfo and CcInfo are good baselines.",
    fields = ["forward_providers"],
)

def _asylo_backend_impl(ctx):
    return [AsyloBackendInfo(forward_providers = [EnclaveInfo, CcInfo])]

asylo_backend = rule(implementation = _asylo_backend_impl, attrs = {})
