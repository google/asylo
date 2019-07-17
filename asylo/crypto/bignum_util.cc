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

#include <endian.h>

#include <algorithm>
#include <cstdlib>
#include <limits>

#include "absl/base/call_once.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

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
    return Status(error::GoogleError::INTERNAL,
                  "Size of BIGNUM changed unexpectedly");
  }
  return bytes;
}

}  // namespace

StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromBigEndianBytes(
    ByteContainerView bytes, Sign sign) {
  bssl::UniquePtr<BIGNUM> bignum(
      BN_bin2bn(bytes.data(), bytes.size(), /*ret=*/nullptr));
  if (bignum == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
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

StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromInteger(int64_t number) {
  int64_t big_endian_absolute_value = htobe64(llabs(number));
  ByteContainerView bytes_view(&big_endian_absolute_value,
                               sizeof(big_endian_absolute_value));
  return BignumFromBigEndianBytes(
      bytes_view, number < 0 ? Sign::kNegative : Sign::kPositive);
}

StatusOr<int64_t> IntegerFromBignum(const BIGNUM &bignum) {
  static absl::once_flag once_init;
  static BIGNUM *int64_min = nullptr;
  static BIGNUM *int64_max = nullptr;
  absl::call_once(once_init, [] {
    int64_min = BignumFromInteger(std::numeric_limits<int64_t>::min())
                    .ValueOrDie()
                    .release();
    int64_max = BignumFromInteger(std::numeric_limits<int64_t>::max())
                    .ValueOrDie()
                    .release();
  });

  if (BN_cmp(&bignum, int64_min) == -1 || BN_cmp(&bignum, int64_max) == 1) {
    return Status(error::GoogleError::OUT_OF_RANGE,
                  "BIGNUM cannot fit in int64_t");
  }

  // This check is necessary because the absolute value of
  // std::numeric_limits<int64_t>::min() cannot fit in an int64_t.
  if (BN_cmp(&bignum, int64_min) == 0) {
    return std::numeric_limits<int64_t>::min();
  }
  std::vector<uint8_t> bytes;
  ASYLO_ASSIGN_OR_RETURN(bytes, AbsoluteValueBigEndianBytesFromBignum(bignum));
  std::reverse(bytes.begin(), bytes.end());
  bytes.resize(sizeof(int64_t), 0);
  int64_t absolute_value = le64toh(*reinterpret_cast<uint64_t *>(bytes.data()));
  return BN_is_negative(&bignum) ? -absolute_value : absolute_value;
}

}  // namespace asylo
