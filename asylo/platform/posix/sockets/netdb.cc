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

#include <netdb.h>
#include <stdlib.h>

#include "asylo/platform/host_call/trusted/host_calls.h"

extern "C" {

// Stub to resolve symbols until functionality is needed
const char *gai_strerror(int ecode) { abort(); }

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  return enc_untrusted_getaddrinfo(node, service, hints, res);
}

void freeaddrinfo(struct addrinfo *res) { enc_freeaddrinfo(res); }

struct servent *getservbyname(const char *name, const char *proto) {
  abort();
}

struct servent *getservbyport(int port, const char *proto) {
  abort();
}

}  // extern "C"
