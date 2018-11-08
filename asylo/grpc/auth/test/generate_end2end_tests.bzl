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

"""Generates build rules for gRPC end2end tests."""

# Name of the enclave gRPC test fixture.
END2END_FIXTURE = "h2_enclave_security_test"

# A list of hand-selected gRPC end2end tests that should be run against the
# enclave gRPC stack. Since we are primarily testing that channel establishment
# is working, it is not necessary to run all the end2end tests.
END2END_TESTS = [
    "invoke_large_request",
    "max_message_length",
    "payload",
    "simple_request",
]

def grpc_end2end_tests():
    for test in END2END_TESTS:
        native.sh_test(
            name = "%s@%s" % (END2END_FIXTURE, test),
            srcs = ["end2end_test.sh"],
            args = ["$(location %s)" % END2END_FIXTURE, test],
            data = [":%s" % END2END_FIXTURE],
        )
