/*
 *
 * Copyright 2017 Asylo authors
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

// Test suite for the OffsetTranslator class.
#include "asylo/platform/storage/utils/offset_translator.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/util/logging.h"

namespace asylo {
namespace {

using platform::storage::OffsetTranslator;

class OffsetTranslatorTest : public ::testing::Test,
                             public ::testing::WithParamInterface<
                                 ::testing::tuple<off_t, off_t, off_t>> {
 protected:
  void FillUpParametersAndCreate();

  std::unique_ptr<OffsetTranslator> translator_;
  size_t header_length_;
  size_t payload_length_;
  size_t block_length_;
};

constexpr off_t kInvalidOffset = OffsetTranslator::kInvalidOffset;

const off_t header_length_vals[] = {10, 40, 120};
const off_t payload_length_vals[] = {10, 40, 120};
const off_t meta_length_vals[] = {10, 40, 120};

INSTANTIATE_TEST_SUITE_P(
    Instance1, OffsetTranslatorTest,
    ::testing::Combine(::testing::ValuesIn(header_length_vals),
                       ::testing::ValuesIn(payload_length_vals),
                       ::testing::ValuesIn(meta_length_vals)));

void OffsetTranslatorTest::FillUpParametersAndCreate() {
  header_length_ = ::testing::get<0>(GetParam());
  payload_length_ = ::testing::get<1>(GetParam());
  block_length_ = ::testing::get<1>(GetParam()) + ::testing::get<2>(GetParam());
  translator_ =
      OffsetTranslator::Create(header_length_, payload_length_, block_length_);
}

TEST(CreateFailureTest, OffsetTranslatorTest) {
  EXPECT_EQ(OffsetTranslator::Create(10, 100, 100), nullptr);
  EXPECT_EQ(OffsetTranslator::Create(0, 100, 140), nullptr);
  EXPECT_EQ(OffsetTranslator::Create(10, 0, 140), nullptr);
}

TEST_P(OffsetTranslatorTest, PhysicalToLogicalTest) {
  FillUpParametersAndCreate();
  ASSERT_NE(translator_, nullptr);
  EXPECT_EQ(translator_->PhysicalToLogical(-1), kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(0), kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(1), kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ - 1), kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_), 0);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + 1), 1);
  EXPECT_EQ(
      translator_->PhysicalToLogical(header_length_ + payload_length_ - 1),
      payload_length_ - 1);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + payload_length_),
            kInvalidOffset);
  EXPECT_EQ(
      translator_->PhysicalToLogical(header_length_ + payload_length_ + 1),
      kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + block_length_ - 1),
            kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + block_length_),
            payload_length_);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + block_length_ + 1),
            payload_length_ + 1);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + block_length_ +
                                           payload_length_ - 1),
            2 * payload_length_ - 1);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + block_length_ +
                                           payload_length_),
            kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + block_length_ +
                                           payload_length_ + 1),
            kInvalidOffset);
  EXPECT_EQ(
      translator_->PhysicalToLogical(header_length_ + 2 * block_length_ - 1),
      kInvalidOffset);
  EXPECT_EQ(translator_->PhysicalToLogical(header_length_ + 2 * block_length_),
            2 * payload_length_);
  EXPECT_EQ(
      translator_->PhysicalToLogical(header_length_ + 2 * block_length_ + 1),
      2 * payload_length_ + 1);
}

TEST_P(OffsetTranslatorTest, LogicalToPhysicalTest) {
  FillUpParametersAndCreate();
  ASSERT_NE(translator_, nullptr);
  EXPECT_EQ(translator_->LogicalToPhysical(-1), kInvalidOffset);
  EXPECT_EQ(translator_->LogicalToPhysical(0), header_length_);
  EXPECT_EQ(translator_->LogicalToPhysical(1), header_length_ + 1);
  EXPECT_EQ(translator_->LogicalToPhysical(payload_length_ - 1),
            header_length_ + payload_length_ - 1);
  EXPECT_EQ(translator_->LogicalToPhysical(payload_length_),
            header_length_ + block_length_);
  EXPECT_EQ(translator_->LogicalToPhysical(payload_length_ + 1),
            header_length_ + block_length_ + 1);
  EXPECT_EQ(translator_->LogicalToPhysical(2 * payload_length_ - 1),
            header_length_ + block_length_ + payload_length_ - 1);
  EXPECT_EQ(translator_->LogicalToPhysical(2 * payload_length_),
            header_length_ + 2 * block_length_);
  EXPECT_EQ(translator_->LogicalToPhysical(2 * payload_length_ + 1),
            header_length_ + 2 * block_length_ + 1);
}

TEST_P(OffsetTranslatorTest, ReduceLogicalRangeToFullLogicalBlocksTest) {
  struct range_to_blocks_test_element {
    off_t logical_offset;
    size_t count;
    size_t expected_first_partial_block_bytes_count;
    size_t expected_last_partial_block_bytes_count;
    size_t expected_full_inclusive_blocks_bytes_count;
  };

  FillUpParametersAndCreate();
  ASSERT_NE(translator_, nullptr);

  off_t payload_length_offset = payload_length_;
  const range_to_blocks_test_element range_to_blocks_test_elements[] = {
      {0, 0, 0, 0, 0},
      {payload_length_offset + payload_length_offset / 2, 0, 0, 0, 0},
      {0, payload_length_ / 2, 0, payload_length_ / 2, payload_length_},
      {0, payload_length_, 0, 0, payload_length_},
      {0, 2 * payload_length_ + payload_length_ / 2, 0, payload_length_ / 2,
       3 * payload_length_},
      {10 * payload_length_offset, payload_length_ / 2, 0, payload_length_ / 2,
       payload_length_},
      {10 * payload_length_offset, payload_length_, 0, 0, payload_length_},
      {10 * payload_length_offset, 2 * payload_length_ + payload_length_ / 2, 0,
       payload_length_ / 2, 3 * payload_length_},
      {10 * payload_length_offset + payload_length_offset / 2,
       payload_length_ / 4, payload_length_ / 4, 0, payload_length_},
      {10 * payload_length_offset + payload_length_offset / 2,
       payload_length_ / 2, payload_length_ / 2, 0, payload_length_},
      {10 * payload_length_offset + payload_length_offset / 2, payload_length_,
       payload_length_ / 2, payload_length_ / 2, 2 * payload_length_},
      {10 * payload_length_offset + payload_length_offset / 2,
       payload_length_ + payload_length_ / 2, payload_length_ / 2, 0,
       2 * payload_length_},
      {10 * payload_length_offset + payload_length_offset / 2,
       2 * payload_length_, payload_length_ / 2, payload_length_ / 2,
       3 * payload_length_},
  };

  size_t first_partial_block_bytes_count;
  size_t last_partial_block_bytes_count;
  size_t full_inclusive_blocks_bytes_count;

  const int tests_count = sizeof(range_to_blocks_test_elements) /
                          sizeof(range_to_blocks_test_element);
  for (int test_idx = 0; test_idx < tests_count; test_idx++) {
    translator_->ReduceLogicalRangeToFullLogicalBlocks(
        range_to_blocks_test_elements[test_idx].logical_offset,
        range_to_blocks_test_elements[test_idx].count,
        &first_partial_block_bytes_count, &last_partial_block_bytes_count,
        &full_inclusive_blocks_bytes_count);

    EXPECT_EQ(first_partial_block_bytes_count,
              range_to_blocks_test_elements[test_idx]
                  .expected_first_partial_block_bytes_count);
    EXPECT_EQ(last_partial_block_bytes_count,
              range_to_blocks_test_elements[test_idx]
                  .expected_last_partial_block_bytes_count);
    EXPECT_EQ(full_inclusive_blocks_bytes_count,
              range_to_blocks_test_elements[test_idx]
                  .expected_full_inclusive_blocks_bytes_count);
  }
}

}  // namespace
}  // namespace asylo
