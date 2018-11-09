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

#ifndef ASYLO_PLATFORM_POSIX_INCLUDE_SEMAPHORE_H_
#define ASYLO_PLATFORM_POSIX_INCLUDE_SEMAPHORE_H_

#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sem_t {
  int count_;
  pthread_mutex_t mu_;
  pthread_cond_t cv_;
} sem_t;

// These calls are supported. Note that sem_init is supported only with
// pshared=0.
int sem_init(sem_t *sem, int pshared, unsigned int value);
int sem_destroy(sem_t *sem);
int sem_post(sem_t *sem);
int sem_wait(sem_t *sem);
int sem_trywait(sem_t *sem);
int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);
int sem_getvalue(sem_t *sem, int *sval);

// Note: the calls below are part of POSIX semaphores but are not supported in
// Asylo.

// int sem_close(sem_t *);
// sem_t *sem_open(const char *, int, ...);
// int sem_unlink(const char *);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_INCLUDE_SEMAPHORE_H_
