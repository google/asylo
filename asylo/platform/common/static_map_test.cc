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

#include <algorithm>
#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/platform/common/static_map.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

class Foo {
 public:
  virtual ~Foo() {}

  virtual std::string Name() const { return "Foo"; }
};

class Bar : public Foo {
 public:
  std::string Name() const override { return "Bar"; }
};

class Baz : public Bar {
 public:
  std::string Name() const override { return "Baz"; }
};

struct BarNamer {
  std::string operator()(const Bar &bar) {
    return absl::StrCat(bar.Name(), bar.Name());
  }
};

// Static map with default key generation.
DEFINE_STATIC_MAP_OF_BASE_TYPE(FooMap, Foo);
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(FooMap, Bar);
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(FooMap, Baz);

// Static map with custom key generation.
DEFINE_STATIC_MAP_OF_BASE_TYPE(BarMap, Bar, BarNamer);
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(BarMap, Baz);

// Empty static map.
DEFINE_STATIC_MAP_OF_BASE_TYPE(BazMap, Baz);

// Tests functionality of a StaticMap with default Namer specialization.
TEST(StaticMapTest, TestStaticMapBasic) {
  EXPECT_EQ(FooMap::Size(), 2);

  auto bar = FooMap::GetValue("Bar");
  EXPECT_NE(bar, FooMap::value_end());
  EXPECT_EQ(bar->Name(), "Bar");

  auto baz = FooMap::GetValue("Baz");
  EXPECT_NE(baz, FooMap::value_end());
  EXPECT_EQ(baz->Name(), "Baz");
}

// Tests functionality of a StaticMap with a specified Namer specialization.
TEST(StaticMapTest, TestStaticMapCustomNamer) {
  EXPECT_EQ(BarMap::Size(), 1);

  auto baz = BarMap::GetValue("BazBaz");
  EXPECT_NE(baz, BarMap::value_end());
  EXPECT_EQ(baz->Name(), "Baz");
}

// Verify that StaticMap::GetValue returns value_end() for an element that
// doesn't exist.
TEST(StaticMapTest, TestGetNonExistentMapElement) {
  auto bad_foo = FooMap::GetValue("BadFoo");
  EXPECT_EQ(bad_foo, FooMap::value_end());
}

// Tests functionality of a StaticMap that has no elements.
TEST(StaticMapTest, TestAccessEmptyStaticMap) {
  EXPECT_EQ(BazMap::Size(), 0);

  auto baz = BazMap::GetValue("Baz");
  EXPECT_EQ(baz, BazMap::value_end());
}

// Tests that the mutable iterator can be used to iterate through a static map.
TEST(StaticMapTest, TestIterator) {
  int count = 0;
  bool found_bar = false;
  bool found_baz = false;

  auto values = FooMap::Values();
  for (auto iter = values.begin(); iter != values.end(); ++iter) {
    ++count;
    if (iter->Name() == "Bar") {
      found_bar = true;
    } else if (iter->Name() == "Baz") {
      found_baz = true;
    }
  }
  EXPECT_EQ(count, FooMap::Size());
  EXPECT_TRUE(found_bar);
  EXPECT_TRUE(found_baz);
}

// Tests that the immutable iterator can be used to iterate through a static
// map.
TEST(StaticMapTest, TestConstIterator) {
  int count = 0;
  bool found_bar = false;
  bool found_baz = false;

  auto values = FooMap::Values();
  for (auto iter = values.cbegin(); iter != values.cend(); ++iter) {
    ++count;
    if (iter->Name() == "Bar") {
      found_bar = true;
    } else if (iter->Name() == "Baz") {
      found_baz = true;
    }
  }
  EXPECT_EQ(count, FooMap::Size());
  EXPECT_TRUE(found_bar);
  EXPECT_TRUE(found_baz);
}

// Tests implicit conversion from mutable to immutable iterator.
TEST(StaticMapTest, TestIteratorConversion) {
  int count = 0;
  bool found_bar = false;
  bool found_baz = false;

  for (FooMap::const_value_iterator iter = FooMap::value_begin();
       iter != FooMap::value_end(); ++iter) {
    ++count;
    if (iter->Name() == "Bar") {
      found_bar = true;
    } else if (iter->Name() == "Baz") {
      found_baz = true;
    }
  }
  EXPECT_EQ(count, FooMap::Size());
  EXPECT_TRUE(found_bar);
  EXPECT_TRUE(found_baz);
}

// Tests that a range-based for loop can be used to iterate through a static
// map.
TEST(StaticMapTest, TestRangeBasedFor) {
  int count = 0;
  bool found_bar = false;
  bool found_baz = false;

  // The following for loop uses the default constructor of the FooMap class as
  // the range expression. This constructor creates a zero-byte object, and the
  // C++ machinery invokes the begin() and end() methods from this expression,
  // which resolve to the correspondingly named static methods from the FooMap
  // class.
  for (const auto &item : FooMap::Values()) {
    ++count;
    if (item.Name() == "Bar") {
      found_bar = true;
    }
    if (item.Name() == "Baz") {
      found_baz = true;
    }
  }
  EXPECT_EQ(count, FooMap::Size());
  EXPECT_TRUE(found_bar);
  EXPECT_TRUE(found_baz);
}

// Tests that an input-iterator-based algorithm can be called using the mutable
// static-map iterator.
TEST(StaticMapTest, TestAlgorithmIterator) {
  auto values = FooMap::Values();
  auto bar_it = std::find_if(values.begin(), values.end(), [](const Foo &foo) {
    return foo.Name() == "Bar";
  });
  EXPECT_NE(bar_it, values.end());
  EXPECT_EQ(bar_it->Name(), "Bar");

  auto yam_it = std::find_if(values.begin(), values.end(), [](const Foo &foo) {
    return foo.Name() == "Yam";
  });
  EXPECT_EQ(yam_it, values.end());
}

// Tests that an input-iterator-based algorithm can be called using the
// immutable static-map iterator.
TEST(StaticMapTest, TestAlgorithmConstIterator) {
  auto values = FooMap::Values();
  auto bar_it =
      std::find_if(values.cbegin(), values.cend(),
                   [](const Foo &foo) { return foo.Name() == "Bar"; });
  EXPECT_NE(bar_it, values.cend());
  EXPECT_EQ(bar_it->Name(), "Bar");

  auto yam_it =
      std::find_if(values.cbegin(), values.cend(),
                   [](const Foo &foo) { return foo.Name() == "Yam"; });
  EXPECT_EQ(yam_it, values.cend());
}

}  // namespace

// In order to leave out the optional argument when creating a static map, the
// Namer template for the value type must be specialized in the
// asylo namespace.
template <>
struct Namer<Foo> {
  std::string operator()(const Foo &foo) { return foo.Name(); }
};

}  // namespace asylo
