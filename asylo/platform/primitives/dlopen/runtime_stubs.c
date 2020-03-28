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

// This file declares stub implementations of symbols required for linking
// against newlib and library components like absl. It is provided here to
// support basic testing pending full integration with the Asylo runtime.
//

int access() { return 0; }
int enclave_close() { return 0; }
int enclave_execve() { return 0; }
int enclave_exit() { return 0; }
int enclave_fcntl() { return 0; }
int enclave_fork() { return 0; }
int enclave_fstat() { return 0; }
int enclave_getpid() { return 0; }
int enclave_kill() { return 0; }
int enclave_link() { return 0; }
int enclave_lseek() { return 0; }
int enclave_mkdir() { return 0; }
int enclave_open() { return 0; }
int enclave_read() { return 0; }
int enclave_stat() { return 0; }
int enclave_unlink() { return 0; }
int enclave_syscall() { return 0; }
int geteuid() { return 0; }
int pthread_cond_broadcast() { return 0; }
int pthread_cond_destroy() { return 0; }
int pthread_cond_init() { return 0; }
int pthread_cond_signal() { return 0; }
int pthread_cond_timedwait() { return 0; }
int pthread_cond_wait() { return 0; }
int pthread_getspecific() { return 0; }
int pthread_key_create() { return 0; }
int pthread_mutex_destroy() { return 0; }
int pthread_mutex_init() { return 0; }
int pthread_mutex_lock() { return 0; }
int pthread_mutex_trylock() { return 0; }
int pthread_mutex_unlock() { return 0; }
int pthread_setspecific() { return 0; }
