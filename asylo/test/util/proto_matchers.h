/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_TEST_UTIL_PROTO_MATCHERS_H_
#define ASYLO_TEST_UTIL_PROTO_MATCHERS_H_

#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/string_view.h"

namespace asylo {

namespace internal {

template <typename MessageT>
class ProtoMatcher {
 public:
  ProtoMatcher(const MessageT &message,
               std::function<bool(const MessageT &, const MessageT &)>
                   message_comparator)
      : message_(message), message_comparator_(std::move(message_comparator)) {}

  void DescribeTo(std::ostream *os) const { Describe(os, "matches"); }

  void DescribeNegationTo(std::ostream *os) const {
    Describe(os, "does not match");
  }

  bool MatchAndExplain(const MessageT &message,
                       ::testing::MatchResultListener *listener) const {
    if (!message_comparator_(message, message_)) {
      *listener << "which doesn't match";
      return false;
    }
    return true;
  }

 private:
  void Describe(std::ostream *os, absl::string_view explanation) const {
    *os << explanation << " " << message_.GetDescriptor()->full_name() << " ";
    ::testing::internal::UniversalPrint(message_, os);
  }

  const MessageT &message_;
  std::function<bool(const MessageT &, const MessageT &)> message_comparator_;
};

}  // namespace internal

// A proto message matches Equally to another if all fields have been
// set to the same value.
template <typename MessageT>
::testing::PolymorphicMatcher<internal::ProtoMatcher<MessageT>> EqualsProto(
    const MessageT &message) {
  std::function<bool(const MessageT &, const MessageT &)> comparator =
      ::google::protobuf::util::MessageDifferencer::Equals;
  return ::testing::MakePolymorphicMatcher(
      internal::ProtoMatcher<MessageT>(message, std::move(comparator)));
}

// A proto message matches Equivalently to another if all fields have
// the same value. This is different than Equals, in that fields with
// default values are compared. Two protos with uninitialized
// (default) values can never be Equal, but could be Equivalent.
template <typename MessageT>
::testing::PolymorphicMatcher<internal::ProtoMatcher<MessageT>> EquivalentProto(
    const MessageT &message) {
  std::function<bool(const MessageT &, const MessageT &)> comparator =
      ::google::protobuf::util::MessageDifferencer::Equivalent;
  return ::testing::MakePolymorphicMatcher(
      internal::ProtoMatcher<MessageT>(message, std::move(comparator)));
}

// A proto message matches Approximately Equally to another if all
// fields have been set equally, except for float fields which are
// instead compared with MathUtil::AlmostEquals().
template <typename MessageT>
::testing::PolymorphicMatcher<internal::ProtoMatcher<MessageT>>
ApproximatelyEqualsProto(const MessageT &message) {
  std::function<bool(const MessageT &, const MessageT &)> comparator =
      ::google::protobuf::util::MessageDifferencer::ApproximatelyEquals;
  return ::testing::MakePolymorphicMatcher(
      internal::ProtoMatcher<MessageT>(message, std::move(comparator)));
}

// A proto message matches Approximately Equivalent to another if all
// fields are equivalent (see EquivalentProto above), except for float
// fields which are instead compared with MathUtil::AlmostEquals().
template <typename MessageT>
::testing::PolymorphicMatcher<internal::ProtoMatcher<MessageT>>
ApproximatelyEquivalentProto(const MessageT &message) {
  std::function<bool(const MessageT &, const MessageT &)> comparator =
      ::google::protobuf::util::MessageDifferencer::ApproximatelyEquivalent;
  return ::testing::MakePolymorphicMatcher(
      internal::ProtoMatcher<MessageT>(message, std::move(comparator)));
}

// A proto message matches Partially(reference_message) if every field that is
// set in reference_message is set to the same value in the matchee message.
template <typename MessageT>
::testing::PolymorphicMatcher<internal::ProtoMatcher<MessageT>> Partially(
    const MessageT &message) {
  std::function<bool(const MessageT &, const MessageT &)> comparator =
      [](const ::google::protobuf::Message &arg, const ::google::protobuf::Message &other) {
        ::google::protobuf::util::MessageDifferencer differ;
        differ.set_scope(::google::protobuf::util::MessageDifferencer::PARTIAL);
        return differ.Compare(other, arg);
      };
  return ::testing::MakePolymorphicMatcher(
      internal::ProtoMatcher<MessageT>(message, std::move(comparator)));
}

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_PROTO_MATCHERS_H_
