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
"""Functions for describing type definitions for generating macros.

Implements the functions for describing and parsing the type definitions. Allows
emitting macros which can be read directly by a C/C++ program, to evaluate the
unresolved values in such macros and then generate include directives, enum
definitions and conversion functions that allow system constants to be converted
from the newlib implementation used by Asylo inside the enclave to target host
implementation on the untrusted side (typically libc).

For each type definition (eg. include directive, enum), a definition and getter
methods are provided. The definition methods accept a type definition one at a
time, while the get methods return all the type definitions under a single
macro.

Finally, a write_output() method is provided, which emits all the type
definitions recorded so far in the definitions file (types.py).
"""

from __future__ import print_function

import collections
import re
import sys

# Stores system header includes as a list. Only header file names are expected
# with or without the .h extension and without the '#include' directive
# prefixed.
_includes = []

# Map from enum names to dictionary of enum properties and their values.
_enum_map = collections.defaultdict(dict)

# Declare prefix to used for C enum declarations and conversion functions.
_prefix = 'kLinux'


def set_prefix(pref):
  """Sets the prefix used for all enum definitions and conversion functions."""
  global _prefix
  _prefix = pref


def include(filename):
  """Accumulates the file includes provided.

  The filename here is expected to be a system header file (included as
  #include <filename>). This system header file is used twice - once for
  resolving values of constants on the target host implementation at compile
  time, then by the generated conversion functions for converting the constant
  values between newlib and the target host implementation at runtime.

  Args:
    filename: The system header file with or without the .h extension, and
      without the <> or #include directive prefixed. Eg. include("sys/types.h")

  Raises:
    ValueError: Invalid include file format provided.
  """
  if re.match(r'[<,"].*?[>,"]', filename):
    raise ValueError(
        'Invalid include format for filename "%s". Please provide the include '
        'file without enclosing pointy brackets <> or quotes "".' % filename)
  if re.match('#include', filename, re.IGNORECASE):
    raise ValueError(
        'Invalid include format for filename "%s". Please provide the filename '
        'without the prefixing #include directive.' % filename)

  _includes.append(filename)


def define_enum(name,
                values,
                default_value_host=0,
                default_value_newlib=0,
                multi_valued=False):
  """Defines a collection of related enumeration values and their properties.

  Args:
    name: Name of the collection of enumeration values.
    values: C Enumeration values provided as a list of strings.
    default_value_host: Default enum value on the target host implementation.
    default_value_newlib: Default enum value in newlib.
    multi_valued: Boolean indicating if the enum values can be combined using
      bitwise OR operations.
  """

  # The enum values here are written twice, once as a string literal, then as an
  # enum value pointing to the actual integer value of the enum. This allows
  # types conversions generator to directly interpret the latter as a valid
  # integer corresponding to the enum value, since casting string to enum value
  # is non-trivial in c++.
  # An example 'values', like ['ENUM_VAL1', 'ENUM_VAL2'] looks like the
  # following stored as a dictionary entry -
  # {ENUM_VAL1, "ENUM_VAL1"}, {ENUM_VAL2, "ENUM_VAL2"}
  _enum_map[name]['values'] = ', '.join(
      '{{{}, "{}"}}'.format(val, val) for val in values)

  _enum_map[name]['default_value_host'] = default_value_host
  _enum_map[name]['default_value_newlib'] = default_value_newlib
  _enum_map[name]['multi_valued'] = multi_valued


def get_prefix():
  """Gets the prefix for generated C enums and conversion functions."""
  return 'const char prefix[] = "{}";\n'.format(_prefix)


def get_includes_as_include_macros():
  """Returns all the includes as line separated #include macros.

  These includes are required by the types conversions generator at compile time
  to infer the values of enums for a given host implementation.
  """
  return ''.join('#include <{}>\n'.format(filename) for filename in _includes)


def get_includes_in_define_macro():
  """Returns all the includes under a #define INCLUDES macro.

  The returned list can be used to generate #include directives by a consumer.
  """
  quoted_includes = ['"{}"'.format(incl) for incl in _includes]
  return '#define INCLUDES {}'.format(', \\\n'.join(quoted_includes))


def get_enums():
  r"""Returns a macro containing all enum descriptions.

  The returned macro is used by types conversions generator to initialize a enum
  description table (enum_properties_table) mapping enum names to a struct
  (EnumProperties) describing the enum properties, including the enum values. A
  typical output of get_enums looks like the following -

  #define ENUMS_INIT \
  {"FcntlCmd", {-1, -1, false, {{F_GETFD, "F_GETFD"}, {F_SETFD, "F_SETFD"}}}}, \
  {"FileFlags", {0, 0, true, {{O_RDONLY, "O_RDONLY"}, {O_WRONLY, "O_WRONLY"}}}}

  Each line contains an enum, and follows the pattern -
  {"EnumName", {defaultValueHost, defaultValueNewlib, isMultivalued,
  {{enum_val1, "enum_val1"}, {enum_val2, "enum_val2"}}}}, \
  """
  enum_row = []
  for enum_name, enum_properties in _enum_map.items():
    enum_row.append('{{{}, {{{}, {}, {}, {{{}}}}}}}'.format(
        '"{}"'.format(enum_name), enum_properties['default_value_host'],
        enum_properties['default_value_newlib'],
        'true' if enum_properties['multi_valued'] else 'false',
        enum_properties['values']))

  return '#define ENUMS_INIT \\\n{}'.format(', \\\n'.join(enum_row))


def write_output(stream=sys.stdout):
  """Writes the macros to a stream, default to stdout."""
  print(get_includes_as_include_macros(), file=stream)
  print(get_includes_in_define_macro(), file=stream)
  print(get_prefix(), file=stream)
  print(get_enums(), file=stream)
