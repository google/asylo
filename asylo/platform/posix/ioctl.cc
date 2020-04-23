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

#include <stdarg.h>
#include <sys/ioctl.h>

#include "asylo/platform/posix/io/io_manager.h"

extern "C" {

int ioctl(int fd, int request, ...) {
  va_list ap;
  va_start(ap, request);
  void *argp = va_arg(ap, void *);
  int result = asylo::io::IOManager::GetInstance().Ioctl(fd, request, argp);
  va_end(ap);
  return result;
}

}  // extern "C"
