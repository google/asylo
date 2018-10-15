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

licenses(["notice"])  # Apache v2.0

load("//asylo/bazel:asylo.bzl", "enclave_test")

cc_test(
    name = "loader_test",
    size = "small",
    srcs = ["loader_test.cc"],
    features = ["fully_static_link"],  # link libc statically
    linkstatic = 1,  # prefer static libraries
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "enclave_address_test",
    srcs = ["enclave_address_test_driver.cc"],
    enclaves = {"enclave": "//asylo/test/util:do_nothing_enclave.so"},
    tags = ["regression"],
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_googletest//:gtest",
    ],
)
