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
#

load("@rules_java//java:defs.bzl", "java_binary", "java_proto_library")

licenses(["notice"])

java_binary(
    name = "quickstart",
    srcs = [
        "src/main/java/com/example/DemoDriver.java",
    ],
    main_class = "com.example.DemoDriver",
    deps = [
        ":demo_java_proto",
        "//asylo:enclave_client_java",
        "@com_google_protobuf//:protobuf_java",
    ],
)

java_proto_library(
    name = "demo_java_proto",
    deps = [
        "//asylo/examples/quickstart/solution:demo_proto",
    ],
)
