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
"""Java dependencies for Asylo"""

load("@rules_jvm_external//:defs.bzl", "maven_install")

def asylo_java_deps():
    """Macro to include Asylo's Java dependencies in a WORKSPACE."""

    maven_install(
        artifacts = [
            "junit:junit:4.13-rc-1",
            "com.google.truth:truth:1.0",
            "org.hamcrest:hamcrest-library:1.3",
        ],
        repositories = [
            "https://jcenter.bintray.com/",
            "https://repo1.maven.org/maven2",
        ],
    )
