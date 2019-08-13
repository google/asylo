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

#include "asylo/identity/sgx/tcb_container_util.h"

#include <cstdint>

#include <google/protobuf/util/message_differencer.h>
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

// Returns a ByteContainerView of |value| as 0x00 or 0x01.
ByteContainerView FromBool(bool value) {
  static constexpr uint8_t kTrue = 1;
  static constexpr uint8_t kFalse = 0;
  return ByteContainerView(value ? &kTrue : &kFalse, sizeof(uint8_t));
}

// Returns a ByteContainerView of |value| as a sequence of bytes in memory.
ByteContainerView FromUint32(const uint32_t &value) {
  return ByteContainerView(&value, sizeof(value));
}

}  // namespace

size_t TcbHash::operator()(const Tcb &tcb) const {
  uint32_t pce_svn = tcb.pce_svn().value();
  std::string serialized;
  ASYLO_CHECK_OK(SerializeByteContainers(
      &serialized, FromBool(tcb.has_components()), tcb.components(),
      FromBool(tcb.has_pce_svn()), FromBool(tcb.pce_svn().has_value()),
      FromUint32(pce_svn)));
  return string_hasher_(serialized);
}

bool TcbEqual::operator()(const Tcb &lhs, const Tcb &rhs) const {
  return google::protobuf::util::MessageDifferencer::Equals(lhs, rhs);
}

size_t RawTcbHash::operator()(const RawTcb &tcbm) const {
  uint32_t pce_svn = tcbm.pce_svn().value();
  std::string serialized;
  ASYLO_CHECK_OK(SerializeByteContainers(
      &serialized, FromBool(tcbm.has_cpu_svn()),
      FromBool(tcbm.cpu_svn().has_value()), tcbm.cpu_svn().value(),
      FromBool(tcbm.has_pce_svn()), FromBool(tcbm.pce_svn().has_value()),
      FromUint32(pce_svn)));
  return string_hasher_(serialized);
}

bool RawTcbEqual::operator()(const RawTcb &lhs, const RawTcb &rhs) const {
  return google::protobuf::util::MessageDifferencer::Equals(lhs, rhs);
}

}  // namespace sgx
}  // namespace asylo
