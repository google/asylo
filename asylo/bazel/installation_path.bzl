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

"""Provides a function to look up a toolchain installation path."""

def _fail_if_directory_does_not_exist(repository_ctx, path, what):
    result = repository_ctx.execute(["test", "-d", path])
    if result.return_code == 0:
        return path
    fail("Install path to " + what + " does not exist: " + path)

def _try_get_file_line1(repository_ctx, path):
    result = repository_ctx.execute(["cat", path])
    if result.return_code == 0:
        # First line of output with no \n:
        return result.stdout.split("\n", 1)[0]
    return None

def installation_path(repository_ctx, file, user_defined, default, what):
    """Looks up an installation location.

    Args:
      repository_ctx: A repository_rule context object.
      file: The file that should contain the installation location.
      user_defined: A path that user may provide to override lookup (may be None).
      default: When both |file| and |user_defined| are unavailable, fall back on
               this value (may be None).
      what: A string for the failure message to indicate which component could not
            retrieve its installation location.

    Returns:
      string: A path to a directory.
    """
    result = ""
    if user_defined:
        result = user_defined
    if not result:
        result = _try_get_file_line1(
            repository_ctx,
            repository_ctx.os.environ["HOME"] +
            "/.asylo/" + file,
        )
    if not result:
        result = _try_get_file_line1(
            repository_ctx,
            "/usr/local/share/asylo/" + file,
        )
    if not result:
        result = default
        what = what + " [default]"
    if not result:
        fail("Unknown install location for " + what)
    return _fail_if_directory_does_not_exist(repository_ctx, result, what)
