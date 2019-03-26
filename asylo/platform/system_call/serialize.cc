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

#include "asylo/platform/system_call/serialize.h"

#include <algorithm>
#include <cstddef>
#include <numeric>

#include "absl/strings/str_cat.h"
#include "asylo/platform/system_call/message.h"
#include "asylo/platform/system_call/metadata.h"

namespace asylo {
namespace system_call {
namespace {

// Returns the sum of the values in a collection.
template <typename T>
typename T::value_type Sum(const T &values) {
  return std::accumulate(values.begin(), values.end(),
                         static_cast<typename T::value_type>(0));
}
}  // namespace

primitives::PrimitiveStatus SerializeRequest(
    int sysno, const std::array<uint64_t, kParameterMax> &parameters,
    primitives::Extent *request,
    const primitives::ExtentAllocator &request_allocator) {
  SystemCallDescriptor descriptor{sysno};
  if (!descriptor.is_valid()) {
    return primitives::PrimitiveStatus{
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Could not infer system call descriptor from the sysno (",
                     sysno, ") provided.")};
  }

  auto writer = MessageWriter::RequestWriter(sysno, parameters);
  size_t size = writer.MessageSize();

  if (request_allocator == nullptr) {
    *request = {reinterpret_cast<uint8_t *>(malloc(size)), size};
  } else {
    *request = request_allocator(size);
  }

  writer.Write(request);
  return primitives::PrimitiveStatus::OkStatus();
}

primitives::PrimitiveStatus SerializeResponse(
    int sysno, uint64_t result,
    const std::array<uint64_t, kParameterMax> &parameters,
    primitives::Extent *response,
    const primitives::ExtentAllocator &response_allocator) {
  SystemCallDescriptor descriptor{sysno};

  if (!descriptor.is_valid()) {
    return primitives::PrimitiveStatus{
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Could not infer system call descriptor from the sysno (",
                     sysno, ") provided.")};
  }

  auto writer = MessageWriter::ResponseWriter(sysno, result, parameters);
  size_t size = writer.MessageSize();

  if (response_allocator == nullptr) {
    *response = {reinterpret_cast<uint8_t *>(malloc(size)), size};
  } else {
    *response = response_allocator(size);
  }

  writer.Write(response);
  return primitives::PrimitiveStatus::OkStatus();
}

}  // namespace system_call
}  // namespace asylo
