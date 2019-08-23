/*
 *
 * Copyright 2019 Asylo authors
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

#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "asylo/platform/posix/io/io_manager.h"

using asylo::io::IOManager;

namespace {

void convert_statvfs(const struct statfs &stat_buf,
                     struct statvfs *statvfs_buf) {
  statvfs_buf->f_bsize = stat_buf.f_bsize;
  statvfs_buf->f_frsize = stat_buf.f_frsize ?: stat_buf.f_bsize;
  statvfs_buf->f_blocks = stat_buf.f_blocks;
  statvfs_buf->f_bfree = stat_buf.f_bfree;
  statvfs_buf->f_bavail = stat_buf.f_bavail;
  statvfs_buf->f_files = stat_buf.f_files;
  statvfs_buf->f_ffree = stat_buf.f_ffree;
  statvfs_buf->f_fsid.__val[0] = stat_buf.f_fsid.__val[0];
  statvfs_buf->f_fsid.__val[1] = stat_buf.f_fsid.__val[1];
  statvfs_buf->f_favail = stat_buf.f_bavail;  // Unsure how to compute.
  statvfs_buf->f_flag = stat_buf.f_flags;
  statvfs_buf->f_namemax = stat_buf.f_namelen;
}

}  // namespace

extern "C" {

int statfs(const char *path, struct statfs *statfs_buffer) {
  return IOManager::GetInstance().StatFs(path, statfs_buffer);
}

int fstatfs(int fd, struct statfs *statfs_buffer) {
  return IOManager::GetInstance().FStatFs(fd, statfs_buffer);
}

int statvfs(const char *path, struct statvfs *statvfs_buffer) {
  struct statfs fsbuf;
  if (int result = statfs(path, &fsbuf)) {
    return result;
  }
  convert_statvfs(fsbuf, statvfs_buffer);
  return 0;
}

int fstatvfs(int fd, struct statvfs *statvfs_buffer) {
  struct statfs fsbuf;
  if (int result = fstatfs(fd, &fsbuf)) {
    return result;
  }
  convert_statvfs(fsbuf, statvfs_buffer);
  return 0;
}

}  // extern "C"
