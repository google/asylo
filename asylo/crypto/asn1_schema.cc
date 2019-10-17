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

#include "asylo/crypto/asn1_schema.h"

#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "asylo/crypto/asn1.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// The schema returned by Asn1Any(). See the documentation of Asn1Any() for an
// explanation of Asn1AnyImpl's behavior.
class Asn1AnyImpl : public Asn1Schema<Asn1Value> {
 public:
  Asn1AnyImpl() = default;

  // From Asn1Schema.
  StatusOr<Asn1Value> Read(const Asn1Value &asn1) const override {
    return asn1;
  }

  // From Asn1Schema.
  StatusOr<Asn1Value> Write(const Asn1Value &value) const override {
    return value;
  }
};

// The schema returned by Asn1ObjectId(). See the documentation of
// Asn1ObjectId() for an explanation of Asn1ObjectIdImpl's behavior.
class Asn1ObjectIdImpl : public Asn1Schema<ObjectId> {
 public:
  Asn1ObjectIdImpl() = default;

  // From Asn1Schema.
  StatusOr<ObjectId> Read(const Asn1Value &asn1) const override {
    return asn1.GetObjectId();
  }

  // From Asn1Schema.
  StatusOr<Asn1Value> Write(const ObjectId &value) const override {
    return Asn1Value::CreateObjectId(value);
  }
};

}  // namespace

std::unique_ptr<Asn1Schema<Asn1Value>> Asn1Any() {
  return absl::make_unique<Asn1AnyImpl>();
}

std::unique_ptr<Asn1Schema<ObjectId>> Asn1ObjectId() {
  return absl::make_unique<Asn1ObjectIdImpl>();
}

}  // namespace asylo
