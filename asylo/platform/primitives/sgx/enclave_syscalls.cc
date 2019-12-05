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

#include <enclave/enclave_syscalls.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>

// This file provides a bridge between Asylo and the newlib C runtime
// library. The functions provided here implement the services libc would
// typically delegate to the operating system.
//
// Asylo prefixes each "system call" implementation with "enclave_." For
// instance, calls to the POSIX function open(2) will delegate to the Asylo
// function enclave_open.
//
// <enclave/enclave_syscalls.h> enumerates the system primitives required by
// newlib.


extern "C" {

int enclave_execve(const char *name, char *const argv[], char *const env[]) {
  abort();
}

int enclave_kill(int pid, int sig) { abort(); }

}  // extern C
