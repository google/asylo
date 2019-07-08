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

"""Generates proto targets in various languages."""

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
