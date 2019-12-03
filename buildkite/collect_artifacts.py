"""Collecting build artifacts from a Build Events JSON file.

This script will collect test result artifacts from a provided Build Events
JSON file and copy them to a destination directory.
See https://docs.bazel.build/versions/master/build-event-protocol.html

Both source BEP file and destination dir are expected to be provided
as required --command-line-parameters.
"""
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

import argparse
import json
import os
import shutil
import urllib.parse
import urllib.request


TEST_RESULTS = "Test Results"
TEST_LOG = "test.log"
TEST_XML = "test.xml"


def copy_test_results(artifacts, destination):
  """Copies Test Results to a destination.

  During copy adjusts filenames to match test labels.

  Args:
    artifacts: Collected artifacts dictionary. TEST_RESULT key will contain
    test result details keyed by a test label.
    Lastly, each test detail is a dictionary containing TEST_LOG and TEST_XML
    keys with list of files as value.
    destination: Destination dir.
  Returns:
    A dictionary of new paths that was produced by the copy procedure
    keyed by test labels.
  """
  copied = {}
  if TEST_RESULTS in artifacts:
    for label, test_data in artifacts[TEST_RESULTS].items():
      copied[label] = []
      for file_name in [TEST_LOG, TEST_XML]:
        if file_name in test_data:
          # Test run attempt will be set to 0 for single test run
          # or to 1 when a test re-runs.
          attempt = 1 if len(test_data[file_name]) > 1 else 0
          for artifact_file in test_data[file_name]:
            try:
              new_path = test_label_to_path(destination, label,
                                            attempt, file_name)
              os.makedirs(os.path.dirname(new_path), exist_ok=True)
              shutil.copyfile(artifact_file, new_path)
              copied[label].append(new_path)
            except IOError as err:
              # If we fail to collect a particular artifact,
              # we don't want to fail the buildkite workflow because the failure
              # is not related to the compilation, tests, or Docker setup.
              # So we will log an error and ignore/continue.
              print(err)
  return copied


def discover(build_events_file):
  """Discovers all build artifacts from a Build Events file.

  Args:
    build_events_file: Path to BEP JSON file (must exist and be readable)
  Returns:
    Dictionary of artifacts keyed by build stage (e.g. test)
    or an empty dictionary if build_events_file does not exist.
  Raises:
    RuntimeError: The build_events_file isn't readable.
  """
  assert build_events_file is not None
  if not os.path.exists(build_events_file):
    print("File {} does not exist - nothing to do!".format(build_events_file))
    return {}

  artifacts = {}
  if not os.access(build_events_file, os.R_OK):
    raise RuntimeError("File {} isn't readable!".format(build_events_file))

  with open(build_events_file, "r", encoding="utf-8") as f:
    bep_data = f.read()

  artifacts[TEST_RESULTS] = discover_test_results(bep_data)
  return artifacts


def discover_test_results(bep_data, status=None):
  """Discovers test results from a Build Events file.

  Args:
    bep_data: BEP data in raw form (must be previously read from the BEP file).
    status: array of desired test statuses to filter.
  Returns:
    Test results dictionary keyed by test names.
  """
  assert bep_data is not None
  test_results = {}
  decoder = json.JSONDecoder()

  # Note that BEP data is not a JSON object but rather a stream of
  # build events, each a JSON object.
  # See https://git.io/JeKjQ
  pos = 0
  while pos < len(bep_data):
    bep_obj, size = decoder.raw_decode(bep_data[pos:])
    if "testSummary" in bep_obj:
      test_target = bep_obj["id"]["testSummary"]["label"]
      test_status = bep_obj["testSummary"]["overallStatus"]
      if status is None or test_status in status:
        outputs = []
        for s in ["passed", "failed"]:
          if s in bep_obj["testSummary"]:
            outputs.extend(bep_obj["testSummary"][s])
        test_logs = []
        for output in outputs:
          test_logs.append(urllib.request.url2pathname(
              urllib.parse.urlparse(output["uri"]).path))
        test_results[test_target] = {
            TEST_LOG: test_logs,
            TEST_XML: [t.replace(TEST_LOG, TEST_XML) for t in test_logs],
            "status": test_status
        }
    pos += size + 1
  return test_results


def test_label_to_path(destination, label, attempt, file_name):
  """Converts a test label and test result file name to a path rooted in destination.

  Args:
    destination: Destination dir where test artifact will be copied
    label: Test Label.
    attempt: Run Attempt.
    file_name: Original filename without a path (test.log or test.xml).
  Returns:
    New Path to be used for the file name.
  """
  _, ext = os.path.splitext(file_name)
  # remove leading //
  path = label[2:]
  path = path.replace("/", os.sep)
  path = path.replace(":", os.sep)
  if attempt == 0:
    path = os.path.join(path, file_name)
  else:
    path = os.path.join(path, "attempt_{}{}".format(attempt, ext))
  return os.path.join(destination, path)


def parse_arguments():
  """Parses command line arguments.

  Returns:
    Parsed arguments as an object.
  """
  parser = argparse.ArgumentParser()
  required = parser.add_argument_group("required arguments")
  required.add_argument("--build-events", "-b", action="store", type=str,
                        help="Path to JSON Build Events File",
                        required=True)
  required.add_argument("--destination", "-d", action="store", type=str,
                        help="Path to a destination directory for artifacts",
                        required=True)
  return parser.parse_args()


def main():
  args = parse_arguments()
  artifacts = discover(args.build_events)
  copied = copy_test_results(artifacts, args.destination)
  n = sum(len(copied[item]) for item in copied)
  print("{}:   Collected {} artifacts for {} {}".format(
      args.build_events, n, len(copied), TEST_RESULTS))


if __name__ == "__main__":
  main()
