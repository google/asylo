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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_CONTAINER_UTIL_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_CONTAINER_UTIL_H_

#include <string>
#include <utility>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>
#include <google/protobuf/util/message_differencer.h>
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"

namespace asylo {
namespace sgx {
namespace internal {

// Defining a specialization of this struct for a particular protobuf message
// type MessageT creates an AbslHashValue() implementation for MessageT based on
// deterministic message serialization.
template <typename MessageT>
struct EnableMessageHashingByDeterministicSerialization;

// Enables the determinstic serialization-based AbslHashValue() implementation
// for Fmspc, Tcb, and RawTcb messages.
template <>
struct EnableMessageHashingByDeterministicSerialization<Fmspc> {};
template <>
struct EnableMessageHashingByDeterministicSerialization<Tcb> {};
template <>
struct EnableMessageHashingByDeterministicSerialization<RawTcb> {};

}  // namespace internal

// An AbslHashValue() implementation for protobuf messages of type MessageT
// based on deterministic message serialization. Only enabled for a given type
// MessageT if there is an EnableMessageHashingByDeterministicSerialization
// specialization for MessageT.
template <
    typename H, typename MessageT,
    typename E =
        internal::EnableMessageHashingByDeterministicSerialization<MessageT>>
H AbslHashValue(H hash, const MessageT &message) {
  std::string serialized;
  // The CodedOutputStream destructor can modify the string to contain garbage
  // bytes.
  {
    google::protobuf::io::StringOutputStream string_stream(&serialized);
    google::protobuf::io::CodedOutputStream coded_stream(&string_stream);
    coded_stream.SetSerializationDeterministic(true);
    CHECK(message.SerializeToCodedStream(&coded_stream));
  }
  return H::combine(std::move(hash), serialized);
}

// An STL-style equality comparator for protobuf messages. Uses
// google::protobuf::util::MessageDifferencer::Equals() to compare messages.
struct MessageEqual {
  bool operator()(const google::protobuf::Message &lhs,
                  const google::protobuf::Message &rhs) const {
    return google::protobuf::util::MessageDifferencer::Equals(lhs, rhs);
  }
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_CONTAINER_UTIL_H_
