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

#include "asylo/crypto/bignum_util.h"

#include <openssl/base.h>
#include <openssl/bn.h>

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// The second argument to pass to BN_set_negative() to set the first argument to
// be negative.
constexpr int kSetNegative = 1;

// Returns the big-endian bytes of the absolute value of |bignum|.
StatusOr<std::vector<uint8_t>> AbsoluteValueBigEndianBytesFromBignum(
    const BIGNUM &bignum) {
  std::vector<uint8_t> bytes(BN_num_bytes(&bignum));
  if (BN_bn2bin(&bignum, bytes.data()) != bytes.size()) {
    return Status(absl::StatusCode::kInternal,
                  "Size of BIGNUM changed unexpectedly");
  }
  return bytes;
}

// Returns the big-endian bytes of the absolute value of |bignum|, zero-padded
// to be as large as |padded_size|.
StatusOr<std::vector<uint8_t>> PaddedAbsoluteValueBigEndianBytesFromBignum(
    const BIGNUM &bignum, size_t padded_size) {
  size_t bignum_bytes_size = BN_num_bytes(&bignum);
  if (bignum_bytes_size > padded_size) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrFormat("Number of bytes in BIGNUM (%d) is larger "
                                  "than the buffer size (%d)",
                                  bignum_bytes_size, padded_size));
  }
  std::vector<uint8_t> bytes(padded_size);
  if (BN_bn2bin_padded(bytes.data(), padded_size, &bignum) != 1) {
    return Status(absl::StatusCode::kInternal, "Serialization failed");
  }
  return bytes;
}

}  // namespace

namespace internal {

bool IsBigEndianSystem() {
  static const uint16_t kOne = 1;
  return *reinterpret_cast<const uint8_t *>(&kOne) == 0;
}

}  // namespace internal

StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromBigEndianBytes(
    ByteContainerView bytes, Sign sign) {
  bssl::UniquePtr<BIGNUM> bignum(
      BN_bin2bn(bytes.data(), bytes.size(), /*ret=*/nullptr));
  if (bignum == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  if (sign == Sign::kNegative) {
    BN_set_negative(bignum.get(), kSetNegative);
  }
  // GCC 4.9 requires this std::move() here.
  return std::move(bignum);
}

StatusOr<std::pair<Sign, std::vector<uint8_t>>> BigEndianBytesFromBignum(
    const BIGNUM &bignum) {
  std::pair<Sign, std::vector<uint8_t>> result;
  result.first = BN_is_negative(&bignum) ? Sign::kNegative : Sign::kPositive;
  ASYLO_ASSIGN_OR_RETURN(result.second,
                         AbsoluteValueBigEndianBytesFromBignum(bignum));
  return result;
}

StatusOr<std::pair<Sign, std::vector<uint8_t>>> PaddedBigEndianBytesFromBignum(
    const BIGNUM &bignum, size_t padded_size) {
  std::pair<Sign, std::vector<uint8_t>> result;
  result.first = BN_is_negative(&bignum) ? Sign::kNegative : Sign::kPositive;
  ASYLO_ASSIGN_OR_RETURN(
      result.second,
      PaddedAbsoluteValueBigEndianBytesFromBignum(bignum, padded_size));
  return result;
}

StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromLittleEndianBytes(
    ByteContainerView bytes, Sign sign) {
  std::vector<uint8_t> big_endian_bytes(bytes.rbegin(), bytes.rend());
  return BignumFromBigEndianBytes(big_endian_bytes, sign);
}

StatusOr<std::pair<Sign, std::vector<uint8_t>>> LittleEndianBytesFromBignum(
    const BIGNUM &bignum) {
  std::pair<Sign, std::vector<uint8_t>> result;
  ASYLO_ASSIGN_OR_RETURN(result, BigEndianBytesFromBignum(bignum));
  std::reverse(result.second.begin(), result.second.end());
  return result;
}

StatusOr<std::pair<Sign, std::vector<uint8_t>>>
PaddedLittleEndianBytesFromBignum(const BIGNUM &bignum, size_t padded_size) {
  std::pair<Sign, std::vector<uint8_t>> result;
  ASYLO_ASSIGN_OR_RETURN(result,
                         PaddedBigEndianBytesFromBignum(bignum, padded_size));
  std::reverse(result.second.begin(), result.second.end());
  return result;
}

}  // namespace asylo
