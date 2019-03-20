#
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
#
"""Declares the include files and symbols to be processed by the code generator.

Describes the types that need to be generated with the default values on the
target implementation.
"""

from asylo.platform.host_call.type_conversions.types_parse_functions import define_enum
from asylo.platform.host_call.type_conversions.types_parse_functions import include
from asylo.platform.host_call.type_conversions.types_parse_functions import set_prefix
from asylo.platform.host_call.type_conversions.types_parse_functions import write_output

include("fcntl.h")

set_prefix("kLinux")

define_enum(
    name="FileStatusFlag",
    values=[
        "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_EXCL",
        "O_TRUNC", "O_NONBLOCK", "O_DIRECT", "O_CLOEXEC"
    ],
    multi_valued=True)

define_enum(
    name="FcntlCommand",
    values=[
        "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL", "F_GETPIPE_SZ",
        "F_SETPIPE_SZ"
    ],
    multi_valued=False,
    default_value_host=-1,
    default_value_newlib=-1)

write_output()
