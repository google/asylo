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

"""Defines a test rule that uses the backend_provider package."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "enclave_info")

def _check_enclave_info_impl(ctx):
    """This rule passes through an executable argument if it is not an enclave."""
    if enclave_info in ctx.attr.executable:
        fail("no enclave info please")

    return [DefaultInfo(runfiles = ctx.runfiles(files = [ctx.file.executable]))]

check_enclave_info_rule = rule(
    implementation = _check_enclave_info_impl,
    attrs = {
        "executable": attr.label(
            mandatory = True,
            executable = True,
            cfg = "host",
            allow_single_file = True,
        ),
    },
)
