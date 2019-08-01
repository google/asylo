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
"""Tests for types_parse_functions."""

from unittest import main
from unittest import TestCase

from asylo.platform.system_call.type_conversions.types_parse_functions import define_enum
from asylo.platform.system_call.type_conversions.types_parse_functions import define_struct
from asylo.platform.system_call.type_conversions.types_parse_functions import get_bridge_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import get_enums
from asylo.platform.system_call.type_conversions.types_parse_functions import get_includes_as_include_macros
from asylo.platform.system_call.type_conversions.types_parse_functions import get_includes_in_define_macro
from asylo.platform.system_call.type_conversions.types_parse_functions import get_klinux_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import get_structs
from asylo.platform.system_call.type_conversions.types_parse_functions import include
from asylo.platform.system_call.type_conversions.types_parse_functions import set_bridge_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import set_klinux_prefix


class TypesParseFunctionsTest(TestCase):
  """Tests for types functions."""

  def test_get_enums_with_only_default_vals(self):
    define_enum('TestEnum', ['a', 'b'])
    self.assertEqual(
        get_enums(), '#define ENUMS_INIT \\\n'
        '{"TestEnum", {0, 0, false, false, false, {{"a", a}, {"b", b}}}}\n')

  def test_get_enums_with_all_vals(self):
    define_enum('TestEnum', ['a'], 1, 2, True, True, True)
    self.assertEqual(
        get_enums(),
        '#define ENUMS_INIT \\\n{"TestEnum", {1, 2, true, true, true, '
        '{{"a", a}}}}\n')

  def test_get_structs_with_only_default_vals(self):
    define_struct('TestStruct', [('a', 'b')])
    self.assertEqual(
        get_structs(), '#define STRUCTS_INIT \\\n'
        '{"TestStruct", {true, false, {{"b", "a"}}}}\n')

  def test_get_structs_with_all_vals(self):
    define_struct('TestStruct', [('a', 'b')], False, True)
    self.assertEqual(
        get_structs(), '#define STRUCTS_INIT \\\n'
        '{"TestStruct", {false, true, {{"b", "a"}}}}\n')

  def test_klinux_prefix(self):
    prefix_string = 'test_prefix'
    set_klinux_prefix(prefix_string)
    self.assertEqual(
        get_klinux_prefix(),
        'const char klinux_prefix[] = "{}";\n'.format(prefix_string))

  def test_bridge_prefix(self):
    prefix_string = 'test_prefix'
    set_bridge_prefix(prefix_string)
    self.assertEqual(
        get_bridge_prefix(),
        'const char bridge_prefix[] = "{}";\n'.format(prefix_string))

  def test_include_exceptions(self):
    with self.assertRaises(ValueError):
      include('<my_header_file>')
    with self.assertRaises(ValueError):
      include('"my_header_file"')
    with self.assertRaises(ValueError):
      include('#include "myheaderfile.h"')

  def test_get_includes(self):
    include('iostream')
    include('stdio')
    self.assertEqual(
        get_includes_as_include_macros(),
        '#include <stdbool.h>\n#include <iostream>\n#include <stdio>\n')
    self.assertEqual(
        get_includes_in_define_macro(),
        '#define INCLUDES "stdbool.h", \\\n"iostream", \\\n"stdio"')


if __name__ == '__main__':
  main()
