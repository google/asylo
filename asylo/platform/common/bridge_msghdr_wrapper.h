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

#ifndef ASYLO_PLATFORM_COMMON_BRIDGE_MSGHDR_WRAPPER_H_
#define ASYLO_PLATFORM_COMMON_BRIDGE_MSGHDR_WRAPPER_H_

#include <sys/socket.h>
#include <vector>

#include "asylo/platform/arch/include/trusted/memory.h"
#include "asylo/platform/common/bridge_types.h"

namespace asylo {

// This helper class wraps a bridge_msghdr and does a deep copy of all the
// buffers to untrusted memory.
class BridgeMsghdrWrapper {
 public:
  explicit BridgeMsghdrWrapper(const struct msghdr *in);
  BridgeMsghdrWrapper(const BridgeMsghdrWrapper &other) = delete;
  BridgeMsghdrWrapper &operator=(const BridgeMsghdrWrapper &other) = delete;
  bridge_msghdr *get_msg() const;
  bool CopyAllBuffers();

 private:
  bool CopyMsgName();
  bool CopyMsgIov();
  bool CopyMsgIovBase();
  bool CopyMsgControl();

  const msghdr *msg_in_;
  UntrustedUniquePtr<bridge_msghdr> msg_out_;
  UntrustedUniquePtr<void> msg_name_ptr_;
  UntrustedUniquePtr<void> msg_iov_ptr_;
  UntrustedUniquePtr<void> msg_control_ptr_;
  std::vector<UntrustedUniquePtr<void>> msg_iov_base_ptrs_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_MSGHDR_WRAPPER_H_
