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

#ifndef ASYLO_CRYPTO_BIGNUM_UTIL_H_
#define ASYLO_CRYPTO_BIGNUM_UTIL_H_

#include <openssl/base.h>
#include <openssl/bn.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/base/call_once.h"
#include "absl/status/status.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Represents the sign of a number. Zero is considered positive, although
// functions taking a number and a Sign as input may accept a negative zero as
// equivalent to positive zero.
enum class Sign { kPositive, kNegative };

// Returns a BIGNUM for the number represented by |bytes|. The |bytes| are
// interpreted as a big-endian integer. If |sign| is kNegative, then the value
// in |bytes| is negated before being returned.
StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromBigEndianBytes(
    ByteContainerView bytes, Sign sign = Sign::kPositive);

// Returns a pair consisting of 1) the sign of |bignum| and 2) the bytes of the
// absolute value of |bignum| in big-endian form without any leading zeros.
//
// This function leaks the value of |bignum| to non-cleansing memory.
StatusOr<std::pair<Sign, std::vector<uint8_t>>> BigEndianBytesFromBignum(
    const BIGNUM &bignum);

// Returns a pair consisting of 1) the sign of |bignum| and 2) the bytes of the
// absolute value of |bignum| in big-endian form with zero-padding to meet
// |padded_size|.
//
// This function leaks the value of |bignum| to non-cleansing memory.
StatusOr<std::pair<Sign, std::vector<uint8_t>>> PaddedBigEndianBytesFromBignum(
    const BIGNUM &bignum, size_t padded_size);

// Returns a BIGNUM for the number represented by |bytes|. The |bytes| are
// interpreted as a little-endian integer. If |sign| is kNegative, then the
// value in |bytes| is negated before being returned.
StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromLittleEndianBytes(
    ByteContainerView bytes, Sign sign = Sign::kPositive);

// Returns a pair consisting of 1) the sign of |bignum| and 2) the bytes of the
// absolute value of |bignum| in little-endian form without any leading zeros.
StatusOr<std::pair<Sign, std::vector<uint8_t>>> LittleEndianBytesFromBignum(
    const BIGNUM &bignum);

// Returns a pair consisting of 1) the sign of |bignum| and 2) the bytes of the
// absolute value of |bignum| in little-endian form with zero-padding to meet
// |padded_size|.
StatusOr<std::pair<Sign, std::vector<uint8_t>>>
PaddedLittleEndianBytesFromBignum(const BIGNUM &bignum, size_t padded_size);

namespace internal {

// Returns true if the host is big-endian and false otherwise.
bool IsBigEndianSystem();

}  // namespace internal

// Returns a BIGNUM representing |number|.
template <typename IntT>
StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromInteger(IntT number) {
  static_assert(std::is_integral<IntT>::value, "IntT must be an integral type");

  Sign sign = Sign::kPositive;
  if (std::is_signed<IntT>::value && number < 0) {
    sign = Sign::kNegative;
    // Note that in two's complement arithmetic, the raw bits in
    // std::numeric_limits<IntT>::min() are the same as the raw bits of the
    // absolute value of std::numeric_limits<IntT>::min()) as an unsigned
    // integer of the same width as IntT.
    number = (number == std::numeric_limits<IntT>::min() ? number : -number);
  }
  ByteContainerView number_view(&number, sizeof(number));
  return internal::IsBigEndianSystem()
             ? BignumFromBigEndianBytes(number_view, sign)
             : BignumFromLittleEndianBytes(number_view, sign);
}

// Returns the value of |bignum| as an IntT. If |bignum| does not fit in an
// IntT, then IntegerFromBignum() returns an OUT_OF_RANGE error.
//
// This function leaks the value of |bignum| to non-cleansing memory.
template <typename IntT>
StatusOr<IntT> IntegerFromBignum(const BIGNUM &bignum) {
  static_assert(std::is_integral<IntT>::value, "IntT must be an integral type");

  static absl::once_flag once_init;
  static BIGNUM *int_t_min = nullptr;
  static BIGNUM *int_t_max = nullptr;
  absl::call_once(once_init, [] {
    int_t_min =
        BignumFromInteger(std::numeric_limits<IntT>::min()).value().release();
    int_t_max =
        BignumFromInteger(std::numeric_limits<IntT>::max()).value().release();
  });

  if (BN_cmp(&bignum, int_t_min) == -1 || BN_cmp(&bignum, int_t_max) == 1) {
    return Status(absl::StatusCode::kOutOfRange,
                  "BIGNUM cannot fit in the desired type");
  }

  // This check is necessary because the absolute value of
  // std::numeric_limits<IntT>::min() cannot fit in an IntT if IntT is signed.
  if (std::is_signed<IntT>::value && BN_cmp(&bignum, int_t_min) == 0) {
    return std::numeric_limits<IntT>::min();
  }

  Sign sign;
  std::vector<uint8_t> bytes;
  ASYLO_ASSIGN_OR_RETURN(std::tie(sign, bytes),
                         LittleEndianBytesFromBignum(bignum));
  bytes.resize(sizeof(IntT), 0);
  if (internal::IsBigEndianSystem()) {
    std::reverse(bytes.begin(), bytes.end());
  }
  IntT absolute_value = *reinterpret_cast<const IntT *>(bytes.data());
  return std::is_unsigned<IntT>::value || sign == Sign::kPositive
             ? absolute_value
             : -absolute_value;
}

}  // namespace asylo

#endif  // ASYLO_CRYPTO_BIGNUM_UTIL_H_
