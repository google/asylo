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

#ifndef ASYLO_CRYPTO_UTIL_BYTES_H_
#define ASYLO_CRYPTO_UTIL_BYTES_H_

#include <openssl/mem.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iterator>

#include "absl/base/attributes.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/logging.h"
#include "asylo/util/cleansing_allocator.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Enum class defining the supported data-safety policies for a Bytes
// object. A Bytes object with Policy value of DataSafety::SAFE cleanses
// its memory when it goes out of scope uses and side-channel-resistant
// comparison for equality testing. On the other hand, a Bytes object with
// Policy value of DataSafety::UNSAFE does not cleanse its memory when it goes
// out of scope and may use side-channel-prone comparison for equality testing.
enum class DataSafety { SAFE, UNSAFE };

// The SafePolicy struct defines a type that can be provided as Policy input to
// the Bytes template. Bytes template instantiations based on SafePolicy
// automatically cleanse their memory and use constant-time memory comparisons.
struct SafePolicy {
  using allocator_type = CleansingAllocator<uint8_t>;
  static constexpr DataSafety policy = DataSafety::SAFE;
};

// The UnsafePolicy struct defines a type that can be provided as Policy input
// to the Bytes template. Bytes template instantiations based on UnsafePolicy
// do not automatically cleanse their memory and do not use constant-time
// memory comparisons.
struct UnsafePolicy {
  using allocator_type = std::allocator<uint8_t>;
  static constexpr DataSafety policy = DataSafety::UNSAFE;
};

// Bytes defines a fixed-size bag of bytes. The template class takes three
// template parameters--|Size|, |Policy|, and |BytesT|. |Size| defines the size
// of the data held by this object object in bytes. |Policy|, which must either
// be SafePolicy or UnsafePolicy, specifies the data-safety policy for data held
// by this object. |BytesT| is a type that is a specialization of this template
// class, and indicates the return type of the Place() method exposed by this
// class.
//
// A Bytes object provides the following contract:
//  1. The in-memory footprint of the object is sized exactly to fit the
//     bytes represented by the object's data. For example, there are no
//     additional alignment or other object bytes around actual data held by
//     the object. Also, there is no vtable associated with the object. In
//     other words, this is a packed, standard-layout object.
//  2. It is always trivially copyable and trivially copy-assignable.
//  3. The address returned by the .data() method is the address of the object
//     itself.
// The above contract makes the Bytes object compatible with the
// AlignedObjectPtr template, and makes it suitable for interacting with
// hardware where certain instructions have specific alignment requirements.
template <size_t Size, typename Policy, typename BytesT>
class Bytes {
 public:
  static_assert(std::is_same<Policy, SafePolicy>::value ||
                    std::is_same<Policy, UnsafePolicy>::value,
                "Invalid value for the template parameter Policy.");
  using value_type = uint8_t;

  // The Bytes template class does not allocate any memory. However, it exposes
  // the allocator_type type-alias. This type alias is used by templatized
  // callers to determine whether their byte-container-type output parameters
  // are self-cleansing. While such a use of the allocator_type type-alias is
  // clearly an abuse, and is not consistent with the use of this type alias by
  // the STL, a more appropriate SFINAE method of determining the
  // self-cleansing ability of byte-container objects was deemed too complex and
  // hard to maintain.
  using allocator_type = typename Policy::allocator_type;
  using policy_type = Policy;
  using iterator = uint8_t *;
  using const_iterator = const uint8_t *;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  // Create a new BytesT object that is "placed" at |offset| within
  // |container|->data(). |container| and |container|->data() remain the
  // property of the caller, but must remain valid as long as the placed object
  // is being used. A placed object must never be destroyed using delete.
  template <typename ContainerT>
  static BytesT *Place(ContainerT *container, size_t offset) {
    PerformStaticChecks();

    static_assert(
        sizeof(typename ContainerT::value_type) == sizeof(value_type),
        "Encountered a container with incompatible size of value type.");
    static_assert(
        !std::is_same<allocator_type, CleansingAllocator<value_type>>::value ||
            std::is_same<
                typename ContainerT::allocator_type,
                CleansingAllocator<typename ContainerT::value_type>>::value,
        "A SafeBytes object can only be placed in a container with "
        "allocator_type that is a CleansingAllocator specialization.");

    // Check for int overflow.
    size_t offset_end = offset + Size;
    if (offset_end < offset || offset_end > container->size()) {
      return nullptr;
    }

    return new (container->data() + offset) BytesT;
  }

  // Mutable begin(), end(), rbegin(), and rend() iterator generators.
  iterator begin() { return data_; }
  iterator end() { return data_ + Size; }
  reverse_iterator rbegin() { return reverse_iterator(end()); }
  reverse_iterator rend() { return reverse_iterator(begin()); }

  // Immutable begin(), end(), rbegin(), and rend() iterator generators.
  const_iterator begin() const { return cbegin(); }
  const_iterator end() const { return cend(); }
  const_reverse_iterator rbegin() const { return crbegin(); }
  const_reverse_iterator rend() const { return crend(); }

  // Immutable cbegin(), cend(), crbegin(), and crend() iterator generators.
  const_iterator cbegin() const { return data_; }
  const_iterator cend() const { return data_ + Size; }
  const_reverse_iterator crbegin() const {
    return const_reverse_iterator(cend());
  }
  const_reverse_iterator crend() const {
    return const_reverse_iterator(cbegin());
  }

  // Fills the internal buffer with the specified byte value.
  void fill(uint8_t value) { replace(0, value, Size); }

  // Sets the internal buffer based on bytes from the specified byte container
  // view. The method assigns min(|view|.size(), |Size|) bytes.
  size_t assign(ByteContainerView view) {
    return assign(view.data(), view.size());
  }

  // Sets the internal buffer to |count| bytes from |ptr|. The method assigns
  // min(|count|, |Size|) bytes.
  size_t assign(const void *ptr, size_t count) {
    return replace(0, ptr, count);
  }

  // Replaces contents in the range [|pos|, |pos| + |view|.size()) with the
  // contents of |view|. |pos| must be less than |Size|, otherwise no contents
  // are replaced. Only replaces min(|view|.size(), |Size| - |pos|) bytes.
  // Returns the number of bytes replaced.
  size_t replace(size_t pos, ByteContainerView view) {
    return replace(pos, view.data(), view.size());
  }

  // Replaces contents in the range [|pos|, |pos| + |count| - 1) with |count|
  // bytes from |ptr|. |pos| must be less than |Size|. Only replaces
  // min(|count|, |Size| - |pos|) bytes. Returns the number of bytes replaced.
  size_t replace(size_t pos, const void *ptr, size_t count) {
    if (pos >= Size) {
      return 0;
    }
    ssize_t replace_size = std::min(Size - pos, count);
    memcpy(data_ + pos, ptr, replace_size);
    return replace_size;
  }

  // Replaces contents in the range [|pos|, |pos| + |count| - 1) with |count|
  // copies of |ch|. |pos| must be greater than or equal to zero and less than
  // |Size|. Only replaces min(|Size| - |pos|, |count|) bytes. Returns the
  // number of bytes replaced.
  size_t replace(size_t pos, uint8_t ch, size_t count) {
    if (pos >= Size) {
      return 0;
    }
    ssize_t replace_size = std::min(Size - pos, count);
    memset(data_ + pos, ch, replace_size);
    return replace_size;
  }

  uint8_t *data() { return data_; }
  const uint8_t *data() const { return data_; }

  // Subscript operator.
  inline uint8_t &operator[](size_t pos) { return data_[pos]; }
  inline const uint8_t &operator[](size_t pos) const { return data_[pos]; }

  // at() method--same as the subscript operator.
  inline uint8_t &at(size_t pos) {
    if (pos < 0 || pos >= Size) {
      LOG(FATAL) << "Index out of bounds.";
    }
    return this->operator[](pos);
  }
  inline const uint8_t &at(size_t pos) const {
    if (pos < 0 || pos >= Size) {
      LOG(FATAL) << "Index out of bounds.";
    }
    return this->operator[](pos);
  }

  // Cleanse the internal buffer using OPENSSL_cleanse. OPENSSL_cleanse
  // (per documentation) cleanses memory by overwriting it with zeros.
  // This behavior is specifically expected, and is verified through a test.
  void Cleanse() { OPENSSL_cleanse(data_, Size); }

  // Determine whether the data held by this object equals the data pointed to
  // a const void pointer. The method performs a side-channel-safe comparison
  // if the Policy parameter is set to DataSafety::SAFE, otherwise it uses
  // memcmp for fast comparison.
  bool Equals(const void *data, size_t size) const {
    if (Size != size) {
      return false;
    }
    if (Policy::policy == DataSafety::SAFE) {
      // Since Policy parameter is set to SAFE, perform constant-time comparison
      // to defend against side-channel leakage.
      return (CRYPTO_memcmp(data_, data, Size) == 0);
    } else {
      // Since Policy parameter is set to UNSAFE, use memcmp for fast
      // comparison.
      return (memcmp(data_, data, Size) == 0);
    }
  }

  // Determine whether the data held by this object equals the data pointed to
  // a byte container view. The method performs a side-channel-safe comparison
  // if the Policy parameter is set to DataSafety::SAFE, otherwise it uses
  // memcmp for fast comparison.
  bool Equals(ByteContainerView other) const {
    return Equals(other.data(), other.size());
  }

  // The resize method is included to provide API compatibility with other
  // byte-container classes such as string and std::vector<uint8_t>.
  // It does not modify the object. Callers writing templated code that
  // utilize resize() functionality from a byte-container must explicitly
  // check whether the new size of the resized container matches its expected
  // size.
  void resize(size_t new_size) const { return; }
  static constexpr size_t size() { return Size; }
  static constexpr DataSafety policy() { return Policy::policy; }

  uint8_t data_[Size];

 protected:
  // The default constructor is defaulted so that Bytes is a trivial class.
  Bytes() = default;

  // Instantiates a new object and copies the input |data|. The size of |data|
  // must be the same as the |Size| template parameter.
  explicit Bytes(const uint8_t (&data)[Size]) {
    PerformStaticChecks();
    assign(data, Size);
  }

  // Instantiates a new object and copies the input |data|. If |size| is
  // larger than the value of the |Size| template parameter on the class, then
  // only |Size| bytes are copied.
  Bytes(const uint8_t *data, size_t size) {
    PerformStaticChecks();
    assign(data, size);
  }

  // Instantiates a new object and copy-in the data from |view|. If the size of
  // |view| is larger than the value of the Size template parameter on the
  // class, then only Size bytes are copied.
  Bytes(ByteContainerView view) {
    PerformStaticChecks();
    assign(view.data(), view.size());
  }

  // Instantiates a new object and copy the data from the input range. If the
  // input data is larger than Size, then only Size bytes are copied.
  template <typename Iterator>
  Bytes(Iterator start, Iterator end) {
    PerformStaticChecks();

    if (end < start) {
      return;
    }

    Iterator new_end = start + std::min(Size, static_cast<size_t>(end - start));
    std::copy(start, new_end, data_);
  }

 private:
  static void PerformStaticChecks() {
    static_assert(sizeof(Bytes) == Size,
                  "Size of the Bytes object is incorrect.");
    static_assert(offsetof(Bytes, data_) == 0,
                  "Offset of the member data_ within the class is incorrect.");
  }
} ABSL_ATTRIBUTE_PACKED;

// Define SafeBytes.
template <size_t Size>
class SafeBytes final : public Bytes<Size, SafePolicy, SafeBytes<Size>> {
 public:
  // Type alias for the base type.
  using base_type = Bytes<Size, SafePolicy, SafeBytes<Size>>;

  // Type-aliases from the base class.
  using value_type = typename base_type::value_type;
  using allocator_type = typename base_type::allocator_type;
  using policy_type = typename base_type::allocator_type;
  using iterator = typename base_type::iterator;
  using const_iterator = typename base_type::const_iterator;
  using reverse_iterator = typename base_type::reverse_iterator;
  using const_reverse_iterator = typename base_type::const_reverse_iterator;

  SafeBytes() = default;

  // The following template constructor requires at least one argument
  // since the 0 argument case is covered by the default constructor. It
  // forwards all its arguments to the constructor of the base type. This
  // template construct is safe because none of the constructors of the base
  // type are marked explicit. As a result, there is no possibility of this
  // constructor exposing an explicit constructor of the base class through this
  // implicit constructor.
  template <typename Arg, typename... Args>
  SafeBytes(Arg &&arg, Args &&... args)
      : base_type(std::forward<Arg>(arg), std::forward<Args>(args)...) {}

  // The equality operator. Performs a side-channel-resistant comparison of
  // |other| with this object.
  template <typename BytesT>
  bool operator==(const BytesT &other) const {
    return base_type::Equals(other.data(), other.size());
  }

  // The inequality operator. Returns negation of the equality operator.
  template <typename BytesT>
  bool operator!=(const BytesT &other) const {
    return !(*this == other);
  }

  // Cleanse the object before destruction.
  ~SafeBytes() { base_type::Cleanse(); }
} ABSL_ATTRIBUTE_PACKED;

// Define UnsafeBytes.
template <size_t Size>
class UnsafeBytes final : public Bytes<Size, UnsafePolicy, UnsafeBytes<Size>> {
 public:
  // Type alias for the base type.
  using base_type = Bytes<Size, UnsafePolicy, UnsafeBytes<Size>>;

  // Type-aliases from the base class.
  using value_type = typename base_type::value_type;
  using allocator_type = typename base_type::allocator_type;
  using policy_type = typename base_type::allocator_type;
  using iterator = typename base_type::iterator;
  using const_iterator = typename base_type::const_iterator;
  using reverse_iterator = typename base_type::reverse_iterator;
  using const_reverse_iterator = typename base_type::const_reverse_iterator;

  // The default constructor, copy and move constructors, copy and move
  // assignment operators, and destructor are all defaulted so that the
  // UnsafeBytes class is a trivial class.
  UnsafeBytes() = default;
  UnsafeBytes(const UnsafeBytes &) = default;
  UnsafeBytes &operator=(const UnsafeBytes &) = default;
  UnsafeBytes(UnsafeBytes &&) = default;
  UnsafeBytes &operator=(UnsafeBytes &&) = default;
  ~UnsafeBytes() = default;

  // The following template constructor requires at least one argument
  // since the 0 argument case is covered by the default constructor. It just
  // forwards all its arguments to the constructor of the base type. This
  // template construct is safe because none of the constructors of the base
  // type are marked explicit. As a result, there is no possibility of this
  // constructor exposing an explicit constructor of the base class through this
  // implicit constructor.
  template <typename Arg, typename... Args>
  UnsafeBytes(Arg &&arg, Args &&... args)
      : base_type(std::forward<Arg>(arg), std::forward<Args>(args)...) {}

  // The equality operator. Since the UnsafeBytes class uses UnsafePolicy to
  // configure its Bytes base class, the Equals method, when invoked on an
  // UnsafeBytes object, performs a non-side-channel-resistant comparison. As a
  // result, this operator invokes |other|.Equals() to make sure that the safety
  // expectation of |other| is followed.
  template <typename BytesT>
  bool operator==(const BytesT &other) const {
    return other.Equals(this->data(), this->size());
  }

  // The inequality operator. Returns negation of the equality operator.
  template <typename BytesT>
  bool operator!=(const BytesT &other) const {
    return !(*this == other);
  }
} ABSL_ATTRIBUTE_PACKED;

// Returns a SafeBytes object created from the hex representation in
// |bytes_hex|. |InputSize| must be an odd number. |bytes_hex| must be a
// null-terminated C string with strlen(bytes_hex) equal to |InputSize - 1|. All
// characters in |bytes_hex| must be valid hex characters.
template <size_t InputSize>
StatusOr<SafeBytes<(InputSize - 1) / 2>> InstantiateSafeBytesFromHexString(
    const char *bytes_hex) {
  SafeBytes<(InputSize - 1) / 2> bytes;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromHexString(
      std::string(bytes_hex, InputSize - 1), &bytes));
  return bytes;
}

// Returns an UnsafeBytes object created from the hex representation in
// |bytes_hex|. |InputSize| must be an odd number. |bytes_hex| must be a
// null-terminated C string with strlen(bytes_hex) equal to |InputSize - 1|. All
// characters in |bytes_hex| must be valid hex characters.
template <size_t InputSize>
StatusOr<UnsafeBytes<(InputSize - 1) / 2>> InstantiateUnsafeBytesFromHexString(
    const char *bytes_hex) {
  UnsafeBytes<(InputSize - 1) / 2> bytes;
  ASYLO_RETURN_IF_ERROR(SetTrivialObjectFromHexString(
      std::string(bytes_hex, InputSize - 1), &bytes));
  return bytes;
}
// Stream-insertion operator for SafeBytes. Writes the hex representation of
// |bytes| into the given |os| stream.
template <size_t Size>
inline std::ostream &operator<<(std::ostream &os,
                                const SafeBytes<Size> &bytes) {
  return os << ConvertTrivialObjectToHexString(bytes);
}

// PrintTo() method that enables gtest to print a SafeBytes object.
template <size_t Size>
inline void PrintTo(const SafeBytes<Size> &bytes, std::ostream *os) {
  *os << bytes;
}

// Stream-insertion operator for UnsafeBytes. Writes the hex representation of
// |bytes| into the given |os| stream.
template <size_t Size>
inline std::ostream &operator<<(std::ostream &os,
                                const UnsafeBytes<Size> &bytes) {
  return os << ConvertTrivialObjectToHexString(bytes);
}

// PrintTo() method that enables gtest to print an UnsafeBytes object.
template <size_t Size>
inline void PrintTo(const UnsafeBytes<Size> &bytes, std::ostream *os) {
  *os << bytes;
}

}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BYTES_H_
