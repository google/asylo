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

workspace(name = "com_google_asylo_backend_provider")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_cc",
    # Commit from 2020 June 03
    urls = ["https://github.com/bazelbuild/rules_cc/archive/5cbd3dfbd1613f71ef29bbb7b10310b81e272975.tar.gz"],
    sha256 = "ce19fea12ee666a0d399e6e15b5a77264f6da2b70f2759adea767c9a7f79b17c",
    strip_prefix = "rules_cc-5cbd3dfbd1613f71ef29bbb7b10310b81e272975",
)
