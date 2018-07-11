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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SYS_TERMIOS_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SYS_TERMIOS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;

#define NCCS 32

struct termios {
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[NCCS];
  speed_t c_ispeed;
  speed_t c_ospeed;
};

#define VMIN 6
#define VTIME 5

#define BRKINT 0000002
#define INPCK 0000020
#define ISTRIP 0000040
#define ICRNL 0000400
#define IXON 0002000

#define OPOST 0000001

#define CS8 0000060

#define ECHO 0000010

#define ISIG 0000001
#define ICANON 0000002
#define IEXTEN 0100000

#define TCSAFLUSH 2

int tcgetattr(int fildes, struct termios *termios_p);

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SYS_TERMIOS_H_
