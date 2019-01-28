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
#include <errno.h>

#include "asylo/util/logging.h"
#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/core/bridge_msghdr_wrapper.h"
#include "asylo/platform/core/untrusted_cache_malloc.h"

namespace asylo {
namespace {

// Allocates untrusted memory and copies the buffer |data| of size |size| to it.
// |addr| is updated to point to the address of the copied memory. It is the
// responsibility of the caller to free the memory pointed to by |addr|.
// It is a fatal error if memory cannot be allocated.
bool CopyToUntrustedMemory(void **addr, void *data, size_t size) {
  if (data && !addr) {
    return false;
  }
  // The operation trivially succeeds if there is nothing to copy.
  if (!data) {
    if (addr) {
      *addr = nullptr;
    }
    return true;
  }

  // Instance of the global memory pool singleton.
  asylo::UntrustedCacheMalloc *untrusted_cache_malloc =
      asylo::UntrustedCacheMalloc::Instance();
  void *outside_enclave = untrusted_cache_malloc->Malloc(size);
  // The operation fails if it cannot allocate the necessary resources.
  LOG_IF(FATAL, !outside_enclave) << "Untrusted memory allocation failed";

  memcpy(outside_enclave, data, size);
  *addr = outside_enclave;
  return true;
}

}  // namespace
}  // namespace asylo

asylo::BridgeMsghdrWrapper::BridgeMsghdrWrapper(const struct msghdr *in) {
  struct bridge_msghdr trusted_bridge_msghdr;
  ToBridgeMsgHdr(in, &trusted_bridge_msghdr);
  struct bridge_msghdr *untrusted_bridge_msghdr = nullptr;
  const bool ret = CopyToUntrustedMemory(
      reinterpret_cast<void **>(&untrusted_bridge_msghdr),
      &trusted_bridge_msghdr, sizeof(struct bridge_msghdr));
  if (ret && untrusted_bridge_msghdr) {
    msg_out_.reset(untrusted_bridge_msghdr);
  }
  msg_in_ = in;
}

bridge_msghdr *asylo::BridgeMsghdrWrapper::get_msg()
    const { return msg_out_.get(); }

bool asylo::BridgeMsghdrWrapper::CopyMsgName() {
  void *tmp_name_ptr = nullptr;
  if (!CopyToUntrustedMemory(&tmp_name_ptr, msg_in_->msg_name,
                             msg_in_->msg_namelen)) {
    return false;
  }
  if (tmp_name_ptr) {
    msg_name_ptr_.reset(tmp_name_ptr);
    msg_out_->msg_name = tmp_name_ptr;
  }
  return true;
}

// It is a fatal error if memory cannot be allocated.
bool asylo::BridgeMsghdrWrapper::CopyMsgIov() {
  // Instance of the global memory pool singleton.
  asylo::UntrustedCacheMalloc *untrusted_cache_malloc =
      asylo::UntrustedCacheMalloc::Instance();
  auto tmp_iov_ptr =
      reinterpret_cast<struct bridge_iovec *>(untrusted_cache_malloc->Malloc(
          msg_in_->msg_iovlen * sizeof(struct bridge_iovec)));
  LOG_IF(FATAL, !tmp_iov_ptr) << "Untrusted memory allocation failed";
  if (tmp_iov_ptr) {
    msg_iov_ptr_.reset(tmp_iov_ptr);
    msg_out_->msg_iov = tmp_iov_ptr;
  }
  for (int i = 0; i < msg_in_->msg_iovlen; ++i) {
    if (!ToBridgeIovec(&msg_in_->msg_iov[i], &msg_out_->msg_iov[i])) {
      LOG(FATAL) << "Iovec allocation failed";
    }
  }
  return true;
}

bool asylo::BridgeMsghdrWrapper::CopyMsgIovBase() {
  for (int i = 0; i < msg_in_->msg_iovlen; ++i) {
    msg_iov_base_ptrs_.push_back(nullptr);
    void *tmp_iov_base_ptr = nullptr;
    if (!CopyToUntrustedMemory(&tmp_iov_base_ptr, msg_in_->msg_iov[i].iov_base,
                               msg_in_->msg_iov[i].iov_len)) {
      return false;
    }
    if (tmp_iov_base_ptr) {
      msg_iov_base_ptrs_[i].reset(tmp_iov_base_ptr);
      msg_out_->msg_iov[i].iov_base = tmp_iov_base_ptr;
    }
  }
  return true;
}

bool asylo::BridgeMsghdrWrapper::CopyMsgControl() {
  void *tmp_control_ptr = nullptr;
  if (!CopyToUntrustedMemory(&tmp_control_ptr, msg_in_->msg_control,
                             msg_in_->msg_controllen)) {
    return false;
  }
  if (tmp_control_ptr) {
    msg_control_ptr_.reset(tmp_control_ptr);
    msg_out_->msg_control = tmp_control_ptr;
  }
  return true;
}

bool asylo::BridgeMsghdrWrapper::CopyAllBuffers() {
  if (!CopyMsgName() || !CopyMsgIov() || !CopyMsgIovBase() ||
      !CopyMsgControl()) {
    return false;
  }
  return true;
}
