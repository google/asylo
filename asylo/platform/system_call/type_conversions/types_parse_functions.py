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
unresolved values in such macros and then generate include directives, constant
definitions and conversion functions that allow system constants to be converted
from the enclave C library implementation used by Asylo to target host
implementation on the untrusted side (typically libc).

For each type definition (eg. define_constants, define_structs), a definition
and getter methods are provided. The definition methods accept a type definition
one at a time, while the get methods return all the type definitions under a
single macro.

Finally, a write_output() method is provided, which emits all the type
definitions recorded so far in the definitions file (types.py).
"""

from __future__ import print_function

import collections
import re
import sys

# Stores system header includes as a set. Only header file names are expected
# with or without the .h extension and without the '#include' directive
# prefixed.
# We include stdbool.h by default so that the generated output (as .inc file) is
# also readable by a C program.
_includes = {'stdbool.h'}

# Map from enum names to dictionary of enum properties and their values.
_enum_map = collections.defaultdict(dict)

# Map from struct names to dictionary of struct properties and its members.
_struct_map = collections.defaultdict(dict)

# Declare the prefix to be used for C enum declarations and conversion
# functions. This prefix should be used for direct conversions between enclave
# C library and host library, ones which do not involve an intermediate bridge.
_klinux_prefix = 'kLinux'


def set_klinux_prefix(prefix):
  """Sets the prefix used for constants definitions and conversion functions.

  Args:
    prefix: Name of the prefix to be applied to a kernel based constant
      definition or conversion function name.
  """
  global _klinux_prefix
  _klinux_prefix = prefix


def define_constants(name,
                     values,
                     include_header_file,
                     multi_valued=False,
                     skip_conversions=False,
                     wrap_macros_with_if_defined=False,
                     data_type='int'):
  """Defines a collection of related constants/macros and their properties.

  Args:
    name: Name of the collection of constants.
    values: Constant names provided as a list of strings.
    include_header_file: The system header file used for resolving values to
      generate the type definition.  The filename here is expected to be a
      system header file (included as #include <filename>). This system header
      file is used twice - once for resolving values of constants on the target
      host implementation at compile time, then by the generated conversion
      functions for converting the constant values between enclave C library and
      the target host C library at runtime.
    multi_valued: Boolean indicating if the constant values can be combined
      using bitwise OR operations.
    skip_conversions: Boolean indicating if generation of types conversion
      functions be skipped, and only constants definitions be generated. Useful
      when conversion functions are complex and need to be written manually, but
      the constants definitions can be generated automatically by resolving the
      constants for the target host implementation.
    wrap_macros_with_if_defined: Boolean indicating if each constant value in
      the collection is to be wrapped inside a #if defined(value) ...#endif
      while generating the conversion functions. This allows define_constants()
      to safely accept constants that might not exist on a particular platform
      or architecture. This parameter is intended for use only with constants
      that are C/C++ macros.
    data_type: String specifying the type of constants, if not int.

  Raises:
    ValueError: Invalid include_header_file format provided.
  """

  # A constant here are written twice, once as a string literal, then as an
  # numerical value pointing to the actual integer value of the constant. This
  # allows types conversions generator to directly interpret the latter as a
  # valid integer corresponding to the constant value, since casting string to
  # enum value is non-trivial in c++.
  # An example 'values', like ['CONST_VAL1', 'CONST_VAL2'] looks like the
  # following stored as a dictionary entry -
  # {"CONST_VAL1", CONST_VAL1}, {"CONST_VAL2", CONST_VAL2}
  _enum_map[name]['values'] = ', '.join(
      '{{"{}", {}}}'.format(val, val) for val in values)

  _enum_map[name]['multi_valued'] = multi_valued
  _enum_map[name]['skip_conversions'] = skip_conversions
  _enum_map[name]['wrap_macros_with_if_defined'] = wrap_macros_with_if_defined
  _enum_map[name]['data_type'] = '"{}"'.format(data_type)
  add_include_header_file(include_header_file)


def add_include_header_file(include_header_file):
  """Adds a system header file to the list of includes to be generated.

  Args:
    include_header_file: Name of the system header file, in the format
      'filename.h'. Do not use <> or "" to wrap the filename.
  """
  if re.match(r'[<,"].*?[>,"]', include_header_file):
    raise ValueError(
        'Invalid include format for filename "%s". Please provide the include '
        'file without enclosing pointy brackets <> or quotes "".' %
        include_header_file)
  if re.match('#include', include_header_file, re.IGNORECASE):
    raise ValueError(
        'Invalid include format for filename "%s". Please provide the filename '
        'without the prefixing #include directive.' % include_header_file)

  _includes.add(include_header_file)


def define_struct(name,
                  values,
                  include_header_file,
                  pack_attributes=True,
                  skip_conversions=False):
  """Defines a collection of structs and their properties.

  Args:
    name: Name of the struct. This should be the same as the struct name used in
      enclave C library and the host C library for the system calls. Eg. 'stat',
      'timeval'
    values: List containing tuples of struct member types and struct member
      names. The struct members names should match the corresponding struct
      member names in the struct from enclave C library and libc. Eg.
      [("int64_t", "st_dev"), ("int64_t", "st_ino")].
    include_header_file: Kernel header file to include to identify |name| as a
      valid kernel struct when generating conversion functions between kernel
      structs and enclave structs.
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

  add_include_header_file(include_header_file)


def get_klinux_prefix():
  """Gets the prefix for generated C enums and conversion functions."""
  return 'const char klinux_prefix[] = "{}";\n'.format(_klinux_prefix)


def get_includes_as_include_macros():
  """Returns all the includes as line separated #include macros.

  These includes are required by the types conversions generator at compile time
  to infer the values of constants for a given host implementation.
  """
  return ''.join(
      '#include <{}>\n'.format(filename) for filename in sorted(_includes))


def get_includes_in_define_macro():
  """Returns all the includes under a #define INCLUDES macro.

  The returned list can be used to generate #include directives by a consumer.
  """
  quoted_includes = ['"{}"'.format(incl) for incl in sorted(_includes)]
  return '#define INCLUDES {}'.format(', \\\n'.join(quoted_includes))


def get_constants():
  r"""Returns a macro containing all constants' description.

  The returned macro is used by types conversions generator to initialize a enum
  description table (enum_properties_table) mapping enum names to a struct
  (EnumProperties) describing the enum properties, including the enum values. A
  typical output of get_constants() looks like the following -

  #define ENUMS_INIT \
  {"FcntlCmd", {false, false, false, "int",
  {{"F_GETFD", F_GETFD}, {"F_SETFD", F_SETFD}}}}, \
  {"FileFlags", {0, 0, true, false, false, false, "int", {{"O_RDONLY",
  O_RDONLY}, {"O_WRONLY", O_WRONLY}}}}

  Each line contains an enum, and has the following pattern -
  {"EnumName", {multi_valued, skip_conversions, wrap_macros_with_if_defined,
  data_type, {{"const_val1", const_val1}, {"const_val2", const_val2}}}}, \
  """
  enum_rows = []
  for enum_name, enum_properties in sorted(_enum_map.items()):
    enum_rows.append(
        '{{{name}, {{{multi_valued}, {skip_conversions}, '
        '{wrap_macros_with_if_defined}, {data_type}, {{{values}}}}}}}'.format(
            name='"{}"'.format(enum_name),
            multi_valued='true' if enum_properties['multi_valued'] else 'false',
            skip_conversions='true'
            if enum_properties['skip_conversions'] else 'false',
            wrap_macros_with_if_defined='true'
            if enum_properties['wrap_macros_with_if_defined'] else 'false',
            data_type=enum_properties['data_type'],
            values=enum_properties['values']))

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
  for struct_name, struct_properties in sorted(_struct_map.items()):
    struct_rows.append(
        '{{{struct}, {{{pack_attributes}, {skip_conversions}, {{{values}}}}}}}'
        .format(
            struct='"{}"'.format(struct_name),
            pack_attributes='true'
            if struct_properties['pack_attributes'] else 'false',
            skip_conversions='true'
            if struct_properties['skip_conversions'] else 'false',
            values=struct_properties['values']))

  return '#define STRUCTS_INIT \\\n{}\n'.format(', \\\n'.join(struct_rows))


def write_output(stream=sys.stdout):
  """Writes the macros to a stream, default to stdout."""
  print(get_includes_as_include_macros(), file=stream)
  print(get_includes_in_define_macro(), file=stream)
  print(get_klinux_prefix(), file=stream)
  print(get_constants(), file=stream)
  print(get_structs(), file=stream)
