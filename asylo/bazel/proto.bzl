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

load("@com_google_protobuf//:protobuf.bzl", "py_proto_library")
load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")

"""Generates proto targets in various languages."""

def asylo_grpc_proto_library(
        name,
        srcs = [],
        deps = [],
        well_known_protos = False,
        generate_mocks = False,
        **kwargs):
    """Generates proto targets in various languages for use by gRPC.

    This macro produces two targets. The given name is for cc_library deps and
    a derived name is for asylo_[grpc_]proto_library deps.

    Args:
      name: Name for cc_grpc_library that must be of the form
            base_name + "_grpc_proto" for use in cc_library dependencies. The
            macro will also produce a proto_library named base_name + "_proto"
            for use in proto_library dependencies.
      srcs: Same as proto_library srcs.
      deps: Same as proto_library deps.
      well_known_protos: Same as grpc_proto_library's well_known_protos.
      generate_mocks: Same as grpc_proto_library's generate_mocks.
      **kwargs: proto_library arguments.
    """
    if not name.endswith("_grpc_proto"):
        fail("Expected asylo_grpc_proto_library name to end with '_grpc_proto'.")
    base_name = name[0:-len("_grpc_proto")]
    proto_name = base_name + "_proto"

    grpc_proto_library(
        name = name,
        srcs = srcs,
        deps = deps,
        has_services = True,
        generate_mocks = generate_mocks,
        well_known_protos = well_known_protos,
        use_external = True,
        **kwargs
    )
    native.proto_library(
        name = proto_name,
        srcs = srcs,
        deps = deps,
        **kwargs
    )

def asylo_proto_library(name, srcs = [], deps = [], **kwargs):
    """Generates proto targets in various languages.

    Args:
      name: Name for proto_library and base for the cc_proto_library name, name +
            "_cc".
      srcs: Same as proto_library deps.
      deps: Same as proto_library deps.
      **kwargs: proto_library arguments.
    """
    if kwargs.get("has_services", False):
        fail("Services are handled with asylo_grpc_proto_library.")
    native.proto_library(
        name = name,
        srcs = srcs,
        deps = deps,
        **kwargs
    )
    native.cc_proto_library(
        name = name + "_cc",
        deps = [":" + name],
        **kwargs
    )

def asylo_py_proto_library(name, srcs = [], deps = [], **kwargs):
    """Generates proto targets for Python.

    Args:
      name: Name for proto_library.
      srcs: Same as py_proto_library deps.
      deps: Ignored, provided for compatibility only.
      **kwargs: proto_library arguments.
    """
    _ignore = [deps]
    py_proto_library(
        name = name,
        srcs = srcs,
        default_runtime = "@com_google_protobuf//:protobuf_python",
        protoc = "@com_google_protobuf//:protoc",
        **kwargs
    )
