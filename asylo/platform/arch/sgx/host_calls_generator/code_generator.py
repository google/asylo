#
# Copyright 2017 Asylo authors
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
"""A Python code generator to generate untrusted function call bridge code.

This is a code generator script that, given a textproto function call
specification, generates the bridge and serialization code to invoke untrusted
functions in the Asylo framework. The code generator uses the Jinja
templating library and several template files to generate the output files.

The input files required by the code generator are:
  1. host_calls.textproto (the specification for which to generate code)
  2. templates/* (the set of template files to use for code generation)

The files generated and output by the code generator are:
  1. generated_bridge.edl
  2. generated_host_calls.cc
  3. generated_ocalls.cc
"""

import os
from absl import app
from absl import flags
from jinja2 import Template
from google.protobuf import text_format
from asylo.platform.arch.sgx.host_calls_generator import host_calls_pb2

FLAGS = flags.FLAGS

flags.DEFINE_string('output_dir', None,
                    'Absolute file path to dump the generated output files.')

# Relative path to the code generator.
CODEGEN_PATH = os.path.dirname(os.path.realpath(__file__))

# Input host call configuration file.
HOST_CALLS_TEXTPROTO_FILE = 'host_calls.textproto'

# Template files to use for code generation.
BRIDGE_EDL_TEMPLATE = 'templates/bridge_edl_template.txt'
HOST_CALLS_TEMPLATE = 'templates/host_calls_template.txt'
OCALLS_TEMPLATE = 'templates/ocalls_template.txt'

# Output files to generate.
BRIDGE_EDL_FILE = 'generated_bridge.edl'
HOST_CALLS_FILE = 'generated_host_calls.cc'
OCALLS_FILE = 'generated_ocalls.cc'

GENERATED_FILE_WARNING = (
    '// This is a generated file. For more details about '
    'how to generate this file\n// see the genrule :generate_host_calls in '
    'this package.')

# Pointer attribute enum aliases for pointer types.
IN = host_calls_pb2.PointerAttributeProto.IN
OUT = host_calls_pb2.PointerAttributeProto.OUT
STRING = host_calls_pb2.PointerAttributeProto.STRING
SIZE = host_calls_pb2.PointerAttributeProto.SIZE
USER_CHECK = host_calls_pb2.PointerAttributeProto.USER_CHECK

# Map from pointer attributes to strings.
ATTRIBUTE_STRING_MAP = {
    IN: 'in',
    OUT: 'out',
    STRING: 'string',
    SIZE: 'size',
    USER_CHECK: 'user_check'
}


def raise_host_call_error(host_call_name, error_message):
  raise ValueError(
      'Error found in host call "%s": %s' % (host_call_name, error_message))


def is_pointer_type(parameter_type):
  """A parameter type is a pointer if the last character in the type is '*'."""
  return parameter_type.endswith('*')


def validate_attribute_expressions(other_parameter_names, parameter_proto):
  """Check for invalid pointer attribute expressions.

  Pointer attribute expressions are currently only supported by the SIZE
  attribute. Valid attribute expressions can take two forms: (i) the name of
  another function parameter in the host call; or (ii) an integer.
  All other expressions are invalid.

  Args:
    other_parameter_names: a list of all parameter names in the host
        call excluding the current parameter to validate.
    parameter_proto: a single parameter protocol buffer to validate.

  Raises:
    ValueError: Invalid attribute expressions specified for parameter.
  """
  for attribute_proto in parameter_proto.pointer_attributes:
    if attribute_proto.attribute == SIZE:
      attribute_expression = attribute_proto.attribute_expression
      if (attribute_expression not in other_parameter_names and
          not attribute_expression.isdigit()):
        raise ValueError(
            'Invalid size attribute expression "%s" given for '
            'parameter "%s"!' % (attribute_expression, parameter_proto.name))
    elif attribute_proto.attribute_expression:
      raise ValueError(
          'Unnecessary attribute expression "%s" given for '
          'non-size attribute of parameter "%s"!' %
          (attribute_proto.attribute_expression, parameter_proto.name))


def validate_pointer_attributes(parameter_proto):
  """Check for duplicate and mismatched pointer attributes.

  We validate the set of pointer attributes specified for each pointer
  parameter to identify potentially conflicting attributes. For example,
  labelling a pointer as IN and USER_CHECK is inconsistent, IN will attempt
  to copy the pointer's memory out of the enclave, while USER_CHECK prevents
  copying memory entirely.

  Args:
    parameter_proto: a single parameter protocol buffer to validate.

  Raises:
    ValueError: Invalid pointer attributes specified for parameter.
  """
  all_attributes = [p.attribute for p in parameter_proto.pointer_attributes]
  if len(all_attributes) != len(set(all_attributes)):
    raise ValueError('Duplicate attributes given for parameter "%s"!' %
                     (parameter_proto.name))
  if not any(attr in [IN, OUT, USER_CHECK] for attr in all_attributes):
    raise ValueError('Pointer copy annotation missing for parameter "%s"!' %
                     (parameter_proto.name))
  if (USER_CHECK in all_attributes and
      (IN in all_attributes or OUT in all_attributes)):
    raise ValueError('Invalid combination of pointer copy annotations given '
                     'for parameter "%s"!' % (parameter_proto.name))
  if STRING in all_attributes and SIZE in all_attributes:
    raise ValueError('Conflicting length and string annotations given for '
                     'parameter "%s"!' % (parameter_proto.name))


def validate_host_calls_proto(host_calls_proto):
  """Check the given host calls proto for semantic errors."""
  if not host_calls_proto.IsInitialized():
    raise ValueError('Textproto file "%s" has missing required fields!' %
                     (HOST_CALLS_TEXTPROTO_FILE))
  for host_call_proto in host_calls_proto.host_calls:
    for parameter_proto in host_call_proto.parameters:
      if is_pointer_type(parameter_proto.type):
        if not parameter_proto.pointer_attributes:
          raise_host_call_error(
              host_call_proto.name, 'Pointer attributes '
              'missing for parameter "%s"!' % (parameter_proto.name))
        try:
          validate_pointer_attributes(parameter_proto)
          other_parameter_names = [
              p.name
              for p in host_call_proto.parameters
              if p.name != parameter_proto.name
          ]
          validate_attribute_expressions(other_parameter_names, parameter_proto)
        except ValueError as error:
          raise_host_call_error(host_call_proto.name, error.message)
      elif parameter_proto.pointer_attributes:
        raise_host_call_error(
            host_call_proto.name, 'Pointer attributes given '
            'for non-pointer parameter "%s"!' % (parameter_proto.name))


def comma_delimit_items(items):
  return ', '.join(items)


def get_attributes_string(parameter_proto):
  attribute_strings = []
  for attribute_proto in parameter_proto.pointer_attributes:
    attribute = attribute_proto.attribute
    attribute_string = ATTRIBUTE_STRING_MAP[attribute]
    if attribute == SIZE:
      attribute_string += '=' + attribute_proto.attribute_expression
    attribute_strings.append(attribute_string)
  return '[' + comma_delimit_items(attribute_strings) + ']'


def comma_separate_bridge_parameters(parameters_proto):
  parameter_strings = []
  for parameter_proto in parameters_proto:
    parameter_string = ''
    if parameter_proto.pointer_attributes:
      parameter_string += get_attributes_string(parameter_proto) + ' '
    parameter_string += parameter_proto.type + ' ' + parameter_proto.name
    parameter_strings.append(parameter_string)
  return comma_delimit_items(parameter_strings)


def comma_separate_parameters(parameters_proto):
  type_name_list = [p.type + ' ' + p.name for p in parameters_proto]
  return comma_delimit_items(type_name_list)


def comma_separate_arguments(parameters_proto):
  name_list = [parameter.name for parameter in parameters_proto]
  return comma_delimit_items(name_list)


def read_input_file(file_name):
  file_path = os.path.join(CODEGEN_PATH, file_name)
  with open(file_path, 'r') as file:
    return file.read()


def fill_template(dictionary, template_file_name):
  template_file_contents = read_input_file(template_file_name)
  template = Template(template_file_contents)
  template.globals['generated_file_warning'] = GENERATED_FILE_WARNING
  template.globals[
      'comma_separate_bridge_parameters'] = comma_separate_bridge_parameters
  template.globals['comma_separate_parameters'] = comma_separate_parameters
  template.globals['comma_separate_arguments'] = comma_separate_arguments
  return template.render(dictionary)


def write_output_file(contents, output_file_name):
  output_file_path = os.path.join(FLAGS.output_dir, output_file_name)
  with open(output_file_path, 'w') as f:
    f.write(contents)


def get_host_calls_dictionary(host_calls_textproto):
  host_calls_proto = text_format.Parse(host_calls_textproto,
                                       host_calls_pb2.HostCallsProto())
  validate_host_calls_proto(host_calls_proto)
  return {'host_calls': host_calls_proto.host_calls}


def main(unused_argv):
  if not FLAGS.output_dir:
    raise RuntimeError('Must specify the directory path to dump the generated '
                       'files (use --output_dir).')

  host_calls_textproto = read_input_file(HOST_CALLS_TEXTPROTO_FILE)
  host_calls_dictionary = get_host_calls_dictionary(host_calls_textproto)

  bridge_edl = fill_template(host_calls_dictionary, BRIDGE_EDL_TEMPLATE)
  host_calls = fill_template(host_calls_dictionary, HOST_CALLS_TEMPLATE)
  ocalls = fill_template(host_calls_dictionary, OCALLS_TEMPLATE)

  write_output_file(bridge_edl, BRIDGE_EDL_FILE)
  write_output_file(host_calls, HOST_CALLS_FILE)
  write_output_file(ocalls, OCALLS_FILE)


if __name__ == '__main__':
  app.run(main)
