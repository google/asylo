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
r"""Preprocess system call definitions for input to the table generator.

This script processes a text file describing a list of Linux system calls into a
format which can be included in C++ source code directly. It first parses a list
of system call descriptions from stdin, then writes a corresponding collection
of macros suitable for use as C++ initialization expressions. The idea here is
to avoid excessive abuse of the C++ preprocessor and use Python to transform a
declarative representation of the Linux system call ABI into C++ instead.

For example, given a declaration like:

  SYSCALL_DEFINE3(write, unsigned int, fd, const char * [bound:count], buf,
                  size_t, count)

This script will emit C++ code like:

#define PARAMETER_BOUNDS_INIT                                                  \
  {{"write", "buf"}, 2}

#define PARAMETER_CONVENTIONS_INIT \
  {SYS_write, {"write", 3, 36}},

#define PARAMETER_TABLE_INIT \
      ...
      {36,                                                                     \
       {"write", 36, "fd", TypeFlags<unsigned int>("write", "fd"),             \
        "unsigned int", EncodingSize<unsigned int>("write", "fd")}},           \
      {37,                                                                     \
       {"write", 37, "buf", TypeFlags<const char *>("write", "buf"),           \
        "const char * ", EncodingSize<const char *>("write", "buf")}},         \
      {38,                                                                     \
       {"write", 38, "count", TypeFlags<size_t>("write", "count"), "size_t",   \
        EncodingSize<size_t>("write", "count")}},                              \
       ...

Please see generate_tables.cc for a details on how and where the generated code
is used.
"""

from __future__ import print_function

import re
import sys


class ParseError(Exception):
  pass


class UserError(Exception):
  pass


class SystemCallTable(object):
  """A collection of Linux system call descriptions."""

  def __init__(self, input_stream):
    """Parses a stream of system call declarations from an input stream."""
    self.declarations = input_stream.read()

    # Discard comments.
    self.declarations = re.sub(
        re.compile('//.*$', re.MULTILINE), '', self.declarations)

    # A dictionary from a system call name to a parameter count.
    self.parameter_count = {}

    # A dictionary mapping from a system call name to the list of parameters
    # declared by that system call.
    self.parameter_list = {}

    # A list of (system call, parameter_name, parameter_type, tag, value)
    # annotations.
    self.annotation_list = []

    # A dictionary mapping a (system_call, parameter) pair to a convention.
    self.convention_table = {}

    # a dictionary mapping a system call name to a list of parameters.
    self.parameter_table = {}

    # Parse the input stream.
    self.parse_includes()
    self.parse_defines()
    self.parse_parameters()

  def parse_includes(self):
    """Collect each 'INCLUDE' directive in the input stream."""

    pattern = re.compile(r'INCLUDE\(\s*\"([^)]*)\"\s*\)')
    self.includes = re.findall(pattern, self.declarations)

  def parse_defines(self):
    """Parse each 'SYSCALL_DEFINE' directive in the input stream."""

    pattern = re.compile(r'SYSCALL_DEFINE(\d)\s*\(([^)]*)\)', re.MULTILINE)
    for definition in re.findall(pattern, self.declarations):
      arity, rest = definition
      split = rest.split(',')

      # 'split' is expected to begin with a system call name followed by a
      # zero or more parameter name, parameter type values at consecutive
      # offsets into the list. Check here that its length is odd as a sanity
      # check.
      if len(split) % 2 != 1:
        raise ParseError('Could not parse definition: ' + definition)

      name = split[0]
      self.parameter_count[name] = arity
      self.parameter_list[name] = [item.strip() for item in split[1:]]

  def parse_parameters(self):
    """Parse each entry in the parameter_list array."""

    for syscall, parameters in self.parameter_list.items():
      for i in range(0, len(parameters) - 1, 2):
        parameter_type = parameters[i].strip()
        parameter_name = parameters[i + 1].strip()

        if parameter_type.find('__user') != -1:
          raise UserError('Type includes __user marker: ' + parameter_type)

        # Translate kernel types which are not directly available in user space.
        parameter_type = re.sub('umode_t', 'unsigned short', parameter_type)
        parameter_type = re.sub('u32', 'uint32_t', parameter_type)
        parameter_type = re.sub('u64', 'uint64_t', parameter_type)

        # Match and remove parameter conventions.
        pattern = r'(\\in_out)|(\\in)|(\\out)'
        conventions = re.findall(pattern, parameter_type)
        parameter_type = re.sub(pattern, '', parameter_type)
        for convention in conventions:
          self.convention_table[(syscall, parameter_name)] = convention

        # Match and remove parameter annotations.
        pattern = r'\[(\w*):\s*([^\]\s]*)\]'
        annotations = re.findall(pattern, parameter_type)
        parameter_type = re.sub(pattern, '', parameter_type)
        for annotation in annotations:
          self.annotation_list.append((syscall, parameter_name, parameter_type,
                                       annotation[0], annotation[1]))

        self.parameter_table[(syscall, i / 2)] = (parameter_name,
                                                  parameter_type)

  def write_includes(self):
    """Emits a list of #include directives required by the generated code."""
    for include in self.includes:
      print('#include <{}>'.format(include))

  def write_annotations(self):
    """Emits a list of initializers from the parsed parameter annotations."""

    bounds = []
    counts = []
    lengths = []
    for syscall, param_name, param_type, annotation_name, annotation_value in \
        self.annotation_list:
      key = '{{"{}", "{}"}}'.format(syscall, param_name)
      if annotation_name == 'bound':
        bind_param_index = self.parameter_list[syscall].index(
            annotation_value) / 2
        bounds.append('{{{}, {}}}'.format(key, bind_param_index))
      if annotation_name == 'count':
        counts.append('{{{}, {}}}'.format(key, annotation_value))
      if annotation_name == 'length':
        bind_param_index = self.parameter_list[syscall].index(
            annotation_value) / 2
        element_size = 'sizeof({})'.format(param_type.strip('* '))
        index_and_size = '{{{}, {}}}'.format(bind_param_index, element_size)
        lengths.append('{{{}, {}}}'.format(key, index_and_size))

    # Write the accumulated annotation tables.
    print('#define PARAMETER_BOUNDS_INIT \\\n  ', end='')
    print(', \\\n  '.join(bounds))
    print()
    print('#define PARAMETER_COUNTS_INIT \\\n  ', end='')
    print(', \\\n  '.join(counts))
    print()
    print('#define PARAMETER_LENGTHS_INIT \\\n', end='')
    print(', \\\n  '.join(lengths))

  def write_conventions(self):
    """"Emits a table of parameter conventions."""
    conventions = []
    for parameter, annotations in self.convention_table.items():
      key = '{{"{}", "{}"}}'.format(parameter[0], parameter[1])
      flags = []
      if '\\in' in annotations:
        flags.append('kIn')
      if '\\out' in annotations:
        flags.append('kOut')
      if '\\in_out' in annotations:
        flags.append('kIn')
        flags.append('kOut')
      conventions.append('{{{}, {}}}'.format(key, ' | '.join(flags)))

    # Write a collection of C++ macros to standard out.
    print('#define PARAMETER_CONVENTIONS_INIT \\\n  ', end='')
    print(', \\\n  '.join(conventions))

  def write_syscalls(self):
    """Writes a table of system calls to standard out."""
    lines = []
    print('#define SYSTEM_CALL_TABLE_INIT \\')
    parameter_offset = 0
    for syscall, count in self.parameter_count.items():
      lines.append('  {{SYS_{}, {{"{}", {}, {}}}}}'.format(
          syscall, syscall, count, parameter_offset))
      parameter_offset += int(count)

    print(',  \\\n'.join(lines))

  def write_parameters(self):
    """Writes a table of system call parameters to standard out."""
    lines = []
    parameter_offset = 0
    print('#define PARAMETER_TABLE_INIT \\')
    for syscall, count in self.parameter_count.items():
      for index in range(0, int(count)):
        parameter_name, typename = self.parameter_table[(syscall, index)]

        # Build an expression that evaluates to the type flags of this
        # parameter.
        type_flags = 'TypeFlags<{}>("{}", "{}")'.format(typename, syscall,
                                                        parameter_name)

        # Build an expression that evaluates to the encoding size of this
        # parameter.
        encoding_size = 'EncodingSize<{}>("{}", "{}")'.format(
            typename, syscall, parameter_name)

        # Build an expression that evaluates to the size of this parameter type.
        element_size = 'ElementSize<{}>("{}", "{}")'.format(
            typename, syscall, parameter_name)

        # Build a parameter table key, value pair.
        lines.append(' {{{}, {{"{}", {}, "{}", {}, "{}", {}, {}}}}}'.format(
            parameter_offset, syscall, parameter_offset, parameter_name,
            type_flags, typename, encoding_size, element_size))

        parameter_offset += 1

    print(',  \\\n'.join(lines))

  def write_tables(self):
    self.write_includes()
    print()
    self.write_annotations()
    print()
    self.write_conventions()
    print()
    self.write_syscalls()
    print()
    self.write_parameters()


syscalls = SystemCallTable(sys.stdin)
syscalls.write_tables()
