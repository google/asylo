/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_UTSNAME_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_UTSNAME_H_

#ifdef __cplusplus
extern "C" {
#endif

// According to IETF RFC 1035, fully qualified domain names, such as those held
// in utsname::nodename, may contain up to 255 characters. Therefore, in Asylo,
// the fields of struct utsname are defined to have length 256 in order to hold
// 255 characters and a null byte.
#define UTSNAME_FIELD_LENGTH 256

struct utsname {
  char sysname[UTSNAME_FIELD_LENGTH];
  char nodename[UTSNAME_FIELD_LENGTH];
  char release[UTSNAME_FIELD_LENGTH];
  char version[UTSNAME_FIELD_LENGTH];
  char machine[UTSNAME_FIELD_LENGTH];

  // The |domainname| field is a GNU extension of POSIX. It is included in glibc
  // if _GNU_SOURCE is defined. It is included unconditionally in Asylo for
  // maximum compatibility.
  char domainname[UTSNAME_FIELD_LENGTH];
};

int uname(struct utsname *buf);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_UTSNAME_H_
