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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_

#include <stdint.h>

struct kernel_stat {
  uint64_t  kernel_st_dev;
  uint64_t  kernel_st_ino;
  uint64_t  kernel_st_nlink;

  uint32_t  kernel_st_mode;
  uint32_t  kernel_st_uid;
  uint32_t  kernel_st_gid;
  uint32_t  kernel_unsed_pad0;
  uint64_t  kernel_st_rdev;
  int64_t   kernel_st_size;
  int64_t   kernel_st_blksize;
  int64_t   kernel_st_blocks;

  uint64_t  kernel_st_atime;
  uint64_t  kernel_st_atime_nsec;
  uint64_t  kernel_st_mtime;
  uint64_t  kernel_st_mtime_nsec;
  uint64_t  kernel_st_ctime;
  uint64_t  kernel_st_ctime_nsec;
  int64_t   kernel_unused[3];
};

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_KERNEL_TYPES_H_
