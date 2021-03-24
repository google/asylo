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

from asylo.platform.system_call.type_conversions.types_parse_functions import define_constants
from asylo.platform.system_call.type_conversions.types_parse_functions import define_struct
from asylo.platform.system_call.type_conversions.types_parse_functions import get_constants
from asylo.platform.system_call.type_conversions.types_parse_functions import get_includes_as_include_macros
from asylo.platform.system_call.type_conversions.types_parse_functions import get_includes_in_define_macro
from asylo.platform.system_call.type_conversions.types_parse_functions import get_klinux_prefix
from asylo.platform.system_call.type_conversions.types_parse_functions import get_structs
from asylo.platform.system_call.type_conversions.types_parse_functions import set_klinux_prefix


class TypesParseFunctionsTest(TestCase):
  """Tests for types functions."""

  def test_get_enums_with_only_default_vals(self):
    define_constants('TestEnum', ['a', 'b'], 'iostream')
    self.assertEqual(
        get_constants(), '#define ENUMS_INIT \\\n'
        '{"TestEnum", {false, false, false, "int", '
        '{{"a", a}, {"b", b}}}}\n')

  def test_get_enums_with_all_vals(self):
    define_constants(
        name='TestEnum',
        values=['a'],
        include_header_file='stdio',
        multi_valued=True,
        skip_conversions=True,
        wrap_macros_with_if_defined=True,
        data_type='int64_t')
    self.assertEqual(
        get_constants(),
        '#define ENUMS_INIT \\\n{"TestEnum", {true, true, true, '
        '"int64_t", {{"a", a}}}}\n')

  def test_get_structs_with_only_default_vals(self):
    define_struct('TestStruct', [('a', 'b')], 'stdio')
    self.assertEqual(
        get_structs(), '#define STRUCTS_INIT \\\n'
        '{"TestStruct", {true, false, {{"b", "a"}}}}\n')

  def test_get_structs_with_all_vals(self):
    define_struct('TestStruct', [('a', 'b')], 'stdio', False, True)
    self.assertEqual(
        get_structs(), '#define STRUCTS_INIT \\\n'
        '{"TestStruct", {false, true, {{"b", "a"}}}}\n')

  def test_klinux_prefix(self):
    prefix_string = 'test_prefix'
    set_klinux_prefix(prefix_string)
    self.assertEqual(
        get_klinux_prefix(),
        'const char klinux_prefix[] = "{}";\n'.format(prefix_string))

  def test_include_header_file_exceptions(self):
    with self.assertRaises(ValueError):
      define_constants('TestEnum1', ['a', 'b'], '<my_header_file>')
    with self.assertRaises(ValueError):
      define_constants('TestEnum2', ['a', 'b'], '"my_header_file"')
    with self.assertRaises(ValueError):
      define_constants('TestEnum', ['a', 'b'], '#include "myheaderfile.h"')

  def test_get_includes(self):
    define_constants('TestEnum1', ['a', 'b'], 'iostream')
    define_constants('TestEnum2', ['a', 'b'], 'stdio')
    self.assertEqual(
        get_includes_as_include_macros(),
        '#include <iostream>\n#include <stdbool.h>\n#include <stdio>\n')
    self.assertEqual(
        get_includes_in_define_macro(),
        '#define INCLUDES "iostream", \\\n"stdbool.h", \\\n"stdio"')


if __name__ == '__main__':
  main()
