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

# Code generator to generate serialization and bridge code for the set of
# automated host calls.

package(
    default_visibility = ["//asylo:implementation"],
)

load("//asylo/bazel:proto.bzl", "asylo_proto_library", "asylo_py_proto_library")

asylo_proto_library(
    name = "host_calls_proto",
    srcs = ["host_calls.proto"],
    visibility = ["//visibility:private"],
)

asylo_py_proto_library(
    name = "host_calls_proto_py",
    srcs = ["host_calls.proto"],
    visibility = ["//visibility:private"],
    deps = ["host_calls_proto"],
)

# The host calls code generator should only be invoked through the
# :generate_host_calls genrule exposed by this package.
py_binary(
    name = "code_generator",
    srcs = ["code_generator.py"],
    # The input files to the code generator are the host calls textproto
    # configuration file and the template files.
    data = [
        "host_calls.textproto",
        "templates/bridge_edl_template.txt",
        "templates/host_calls_template.txt",
        "templates/ocalls_template.txt",
    ],
    visibility = ["//visibility:private"],
    deps = [
        ":host_calls_proto_py",
        "@io_abseil_py//absl:app",
        "@io_abseil_py//absl/flags",
        "@jinja//:jinja2",
    ],
)

genrule(
    name = "generate_host_calls",
    outs = [
        "generated_bridge.edl",
        "generated_host_calls.cc",
        "generated_ocalls.cc",
    ],
    cmd = "$(location :code_generator) --output_dir=$(@D)",
    tools = [":code_generator"],
)

py_test(
    name = "code_generator_test",
    srcs = ["code_generator_test.py"],
    deps = [
        ":code_generator",
    ],
)
