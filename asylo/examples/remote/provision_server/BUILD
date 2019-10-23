#
# Copyright 2019 Asylo authors
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

licenses(["notice"])  # Apache v2.0

genrule(
    name = "decoded_certs",
    testonly = True,
    srcs = [
        ":base64_server_cert",
        ":base64_server_key",
    ],
    outs = [
        "server.crt",
        "server.key",
    ],
    cmd = """
    base64 -d $(location base64_server_cert) > $(location server.crt)
    base64 -d $(location base64_server_key) > $(location server.key)
    """,
)

filegroup(
    name = "certs",
    srcs = [
        "server.crt",
        "server.key",
    ],
    visibility = ["//visibility:public"],
)
