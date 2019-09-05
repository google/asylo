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

#include <cstdint>
#include <utility>
#include <vector>

#include "asylo/crypto/util/byte_container_view.h"
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

// Returns a BIGNUM representing |number|.
StatusOr<bssl::UniquePtr<BIGNUM>> BignumFromInteger(int64_t number);

// Returns the value of |bignum| as an int64_t. If |bignum| does not fit in an
// int64_t, then IntegerFromBignum() returns an OUT_OF_RANGE error.
//
// This function leaks the value of |bignum| to non-cleansing memory.
StatusOr<int64_t> IntegerFromBignum(const BIGNUM &bignum);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_BIGNUM_UTIL_H_
