/*
 *
 * Copyright 2017 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "asylo/platform/core/enclave_config_util.h"

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "asylo/util/logging.h"

namespace asylo {
namespace {

// Retrieves the host name using the gethostname(2) system call, and sets the
// host_name field of |config| accordingly.
void SetDefaultHostName(EnclaveConfig *config) {
  // Do nothing if |host_name| field is set already.
  if (config->has_host_name()) return;

  // Set the field to this host name.
#ifdef HOST_NAME_MAX
  char buf[HOST_NAME_MAX + 1];
#else
  char buf[256];
#endif
  if (gethostname(buf, sizeof(buf)) != 0) {
    LOG(ERROR) << "gethostname on host failed:" << strerror(errno);
    return;
  }
  buf[sizeof(buf) - 1] = '\0';
  config->set_host_name(buf);
}

// Retrieves the current working directory using the getcwd(3) system call, and
// sets the current_working_directory field of |config| accordingly.
void SetDefaultCurrentWorkingDirectory(EnclaveConfig *config) {
  // Do nothing if |current_working_directory| field is set already.
  if (config->has_current_working_directory()) return;

  // Set the field to the host's current working directory.
  char buf[PATH_MAX];
  if (!getcwd(buf, sizeof(buf))) {
    LOG(ERROR) << "getcwd on host failed:" << strerror(errno);
    return;
  }
  buf[sizeof(buf) - 1] = '\0';
  config->set_current_working_directory(buf);
}

}  // namespace

void SetEnclaveConfigDefaults(const HostConfig &/*host_config*/,
                              EnclaveConfig *config) {
  SetDefaultHostName(config);
  SetDefaultCurrentWorkingDirectory(config);
}

void SetEnclaveConfigDefaults(EnclaveConfig *config) {
  SetDefaultHostName(config);
  SetDefaultCurrentWorkingDirectory(config);
}

EnclaveConfig CreateDefaultEnclaveConfig(const HostConfig &host_config) {
  EnclaveConfig config;
  SetEnclaveConfigDefaults(host_config, &config);
  return config;
}

EnclaveConfig CreateDefaultEnclaveConfig() {
  EnclaveConfig config;
  SetEnclaveConfigDefaults(&config);
  return config;
}

}  // namespace asylo
