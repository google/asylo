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
# We include stdbool.h by default so that the generated output (as .inc file) is
# also readable by a C program.
_includes = ['stdbool.h']

# Map from enum names to dictionary of enum properties and their values.
_enum_map = collections.defaultdict(dict)

# Map from struct names to dictionary of struct properties and its members.
_struct_map = collections.defaultdict(dict)

# Declare the prefix to be used for C enum declarations and conversion
# functions. This prefix should be used for direct conversions between newlib
# and host library, ones which do not involve an intermediate bridge.
_klinux_prefix = 'kLinux'


def set_klinux_prefix(pref):
  """Sets the prefix used for enum definitions and conversion functions."""
  global _klinux_prefix
  _klinux_prefix = pref


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
                multi_valued=False,
                skip_conversions=False,
                or_input_to_default_value=False):
  """Defines a collection of related enumeration values and their properties.

  Args:
    name: Name of the collection of enumeration values.
    values: C Enumeration values provided as a list of strings.
    default_value_host: Default enum value on the target host implementation.
      This can be an actual int value or the enum value provided as a string.
    default_value_newlib: Default enum value in newlib. This can be an actual
      int value or the enum value provided as a string.
    multi_valued: Boolean indicating if the enum values can be combined using
      bitwise OR operations.
    skip_conversions: Boolean indicating if generation of types conversion
      functions be skipped, and only enum definitions be generated. Useful when
      conversion functions are complex and need to be written manually, but the
      enum definitions can be generated automatically by resolving the enum
      values from the target host implementation.
    or_input_to_default_value: Boolean indicating if the input be bitwise OR'ed
      with default_value_host (or default_value_newlib) in the generated
      conversion function, if no match for the input enum value is found. This
      is useful for cases when we wish to preserve the input for debugging,
      while providing a default output in case no matching enum value for the
      input is found.
  """

  # The enum values here are written twice, once as a string literal, then as an
  # enum value pointing to the actual integer value of the enum. This allows
  # types conversions generator to directly interpret the latter as a valid
  # integer corresponding to the enum value, since casting string to enum value
  # is non-trivial in c++.
  # An example 'values', like ['ENUM_VAL1', 'ENUM_VAL2'] looks like the
  # following stored as a dictionary entry -
  # {"ENUM_VAL1", ENUM_VAL1}, {"ENUM_VAL2", ENUM_VAL2}
  _enum_map[name]['values'] = ', '.join(
      '{{"{}", {}}}'.format(val, val) for val in values)

  _enum_map[name]['default_value_host'] = default_value_host
  _enum_map[name]['default_value_newlib'] = default_value_newlib
  _enum_map[name]['multi_valued'] = multi_valued
  _enum_map[name]['skip_conversions'] = skip_conversions
  _enum_map[name]['or_input_to_default_value'] = or_input_to_default_value


def define_struct(name, values, pack_attributes=True, skip_conversions=False):
  """Defines a collection of structs and their properties.

  Args:
    name: Name of the struct. This should be the same as the struct name used in
      newlib/libc libraries for the system calls. Eg. 'stat', 'timeval'
    values: List containing tuples of struct member types and struct member
      names. The struct members names should match the corresponding struct
      member names in the struct from newlib/libc. Eg. [("int64_t", "st_dev"),
      ("int64_t", "st_ino")].
    pack_attributes: Boolean indicating if the compiler should be prevented from
      padding the generated kernel struct members from their natural alignment.
    skip_conversions: Boolean indicating if generation of types conversion
      functions be skipped, and only kernel struct definitions be generated.
      Useful when kernel conversion functions are complex and need to be written
      manually, but the struct definitions can be generated automatically.
  """
  _struct_map[name]['values'] = ', '.join(
      '{{"{}", "{}"}}'.format(member_name, member_type)
      for member_type, member_name in values)
  _struct_map[name]['pack_attributes'] = pack_attributes
  _struct_map[name]['skip_conversions'] = skip_conversions


def get_klinux_prefix():
  """Gets the prefix for generated C enums and conversion functions."""
  return 'const char klinux_prefix[] = "{}";\n'.format(_klinux_prefix)


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
  {"FcntlCmd", {-1, -1, false, false, false, {{"F_GETFD", F_GETFD}, {"F_SETFD",
  F_SETFD}}}}, \
  {"FileFlags", {0, 0, true, false, false, {{"O_RDONLY", O_RDONLY}, {"O_WRONLY",
  O_WRONLY}}}}

  Each line contains an enum, and has the following pattern -
  {"EnumName", {defaultValueHost, defaultValueNewlib, multi_valued,
  skip_conversions, or_input_to_default_value, {{"enum_val1", enum_val1},
  {"enum_val2", enum_val2}}}}, \
  """
  enum_rows = []
  for enum_name, enum_properties in _enum_map.items():
    enum_rows.append('{{{}, {{{}, {}, {}, {}, {}, {{{}}}}}}}'.format(
        '"{}"'.format(enum_name), enum_properties['default_value_host'],
        enum_properties['default_value_newlib'],
        'true' if enum_properties['multi_valued'] else 'false',
        'true' if enum_properties['skip_conversions'] else 'false',
        'true' if enum_properties['or_input_to_default_value'] else 'false',
        enum_properties['values']))

  return '#define ENUMS_INIT \\\n{}\n'.format(', \\\n'.join(enum_rows))


def get_structs():
  r"""Returns a macro containing all struct descriptions.

  The returned macro is used by types conversion generator to initialize a
  struct description table (struct_properties_table) mapping struct names to a
  struct (StructProperties) describing the struct properties, including struct
  members. A typical output of get_structs looks like the following -

  #define STRUCTS_INIT \
  {"stat", {true, false, {{"st_dev", "int64_t"}, {"st_ino", "int64_t"}}}}, \
  {"timespec", {true, false, {{"tv_sec", "int64_t"}, {"tv_nsec", "int64_t"}}}}

  Each line contains a struct, and has the following pattern -
  {"struct_name", {pack_attributes, skip_conversions, \
  {{"member_name1", "member_type1"}, {"member_name2", "member_type2"}}}}
  """
  struct_rows = []
  for struct_name, struct_properties in _struct_map.items():
    struct_rows.append('{{{}, {{{}, {}, {{{}}}}}}}'.format(
        '"{}"'.format(struct_name),
        'true' if struct_properties['pack_attributes'] else 'false',
        'true' if struct_properties['skip_conversions'] else 'false',
        struct_properties['values']))

  return '#define STRUCTS_INIT \\\n{}\n'.format(', \\\n'.join(struct_rows))


def write_output(stream=sys.stdout):
  """Writes the macros to a stream, default to stdout."""
  print(get_includes_as_include_macros(), file=stream)
  print(get_includes_in_define_macro(), file=stream)
  print(get_klinux_prefix(), file=stream)
  print(get_enums(), file=stream)
  print(get_structs(), file=stream)
