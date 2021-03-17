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

#ifndef ASYLO_PLATFORM_STORAGE_UTILS_RECORD_STORE_H_
#define ASYLO_PLATFORM_STORAGE_UTILS_RECORD_STORE_H_

#include <algorithm>
#include <iterator>
#include <list>
#include <type_traits>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/storage/utils/random_access_storage.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A persistent collection of records of a generic type T. T must be a POD type.
//
// This class provides methods to access a storage resource as a collection of
// fixed-size records of type T. Each record in the collection is addressed by
// its byte offset into a storage resource. The RecordStore does not manage the
// layout of records and it is the responsibility of the caller to ensure that
// records do not overlap. The RecordStore does not take ownership of the
// underlying storage resource: Many instances may wrap the same I/O object at
// the same time, for instance to manage a file containing multiple kinds of
// record along side other kinds of data.
//
// Read and write operations are performed via a fixed-size cache using a least-
// recently-used eviction policy. The cache may be flushed to disk explicitly
// via Flush(), and is automatically flushed when the RecordStore passes out of
// scope.
//
// This class is not thread-safe. It is the responsibility of the caller to
// ensure that its methods are not called concurrently.
template <typename T>
class RecordStore {
 public:
  using value_type = T;

  // Check that reading an object of type T from storage makes sense.
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "T must satisfy std::is_trivially_copy_assignable");

  // Initializes a RecordStore backed by a storage resource |io| and configures
  // a cache with a |capacity| specified as a count of elements of type T. The
  // RecordStore does not take ownership of |io| and it is the responsibility of
  // the caller to ensure it remains valid over the lifetime of the RecordStore.
  RecordStore(size_t capacity, RandomAccessStorage *io)
      : capacity_(std::max<size_t>(capacity, 1)), count_(0), io_(io) {}

  RecordStore(const RecordStore<T> &) = delete;

  RecordStore(RecordStore<T> &&) = default;

  RecordStore &operator=(const RecordStore<T> &) = delete;

  RecordStore &operator=(RecordStore<T> &&) = default;

  // Flush the cache to disk and finalizes the RecordStore.
  ~RecordStore() {
    Status status = Flush();
    LOG_IF(ERROR, !status.ok()) << "Could not flush cache: " << status;
    status = io_->Sync();
    LOG_IF(ERROR, !status.ok()) << "Could not synchronize file: " << status;
  }

  // Flushes the cache to persistent storage and ensures the underlying storage
  // resource has been synchronized. Returns an error status on failure.
  ASYLO_MUST_USE_RESULT Status Flush() {
    for (auto it = cache_.begin(); it != cache_.end(); it++) {
      ASYLO_RETURN_IF_ERROR(Commit(it));
    }
    ASYLO_RETURN_IF_ERROR(io_->Sync());
    return absl::OkStatus();
  }

  // Reads a record from storage into |item|, returning an error status on
  // failure. |offset| specifies a byte-offset into the underlying storage
  // resource. The returned value may be read from cache, in which case it will
  // reflect the value written via this instance and not the value on disk if it
  // has been modified otherwise.
  ASYLO_MUST_USE_RESULT Status Read(off_t offset, T *item) {
    auto it = index_.find(offset);
    if (it != index_.end()) {
      MoveToFront(it->second);
    } else {
      if (count_ < capacity_) {
        cache_.emplace_front();
        count_++;
      } else {
        ASYLO_RETURN_IF_ERROR(Evict());
      }
      auto first = cache_.begin();
      Status status = io_->Read(&first->value, offset, sizeof(T));
      if (!status.ok()) {
        // On read failure, the contents of the head node are undefined. Discard
        // the cache head node to ensure garbage data is not evicted and written
        // back to disk.
        cache_.pop_front();
        count_--;
        return status;
      }
      first->offset = offset;
      first->dirty = false;
      index_[offset] = first;
    }
    *item = cache_.begin()->value;
    return absl::OkStatus();
  }

  // Writes |item| to the record store, returning an error status on failure.
  // |offset| specifies a byte-offset into the underlying storage resource. Note
  // that the caller is responsible for managing the layout of records in
  // storage and it is an error to write overlapping elements to the
  // RecordStore. Writes are cached and may not be persisted to storage until
  // Flush() is called or the RecordStore is destroyed.
  ASYLO_MUST_USE_RESULT Status Write(off_t offset, const T &item) {
    auto it = index_.find(offset);
    if (it != index_.end()) {
      MoveToFront(it->second);
    } else {
      if (count_ < capacity_) {
        // Allocate a new cache entry. Note that existing iterators into cache_
        // are not invalidated.
        cache_.emplace_front();
        count_++;
      } else {
        ASYLO_RETURN_IF_ERROR(Evict());
      }
      cache_.begin()->offset = offset;
      index_[offset] = cache_.begin();
    }
    auto first = cache_.begin();
    first->value = item;
    first->dirty = true;
    return absl::OkStatus();
  }

  // Returns true if a record specified by its byte-offset is present in the
  // cache.
  bool IsCached(off_t offset) const { return index_.contains(offset); }

 private:
  struct CacheEntry {
    off_t offset;  // Byte offset of this record.
    T value;       // Cached record value.
    bool dirty;    // True if this entry has been modified.
  };

  using NodeRef = typename std::list<CacheEntry>::iterator;
  using ConstNodeRef = typename std::list<CacheEntry>::const_iterator;

  // Writes a cache entry to storage, returning an error status on failure.
  ASYLO_MUST_USE_RESULT Status Commit(NodeRef entry) {
    ASYLO_RETURN_IF_ERROR(io_->Write(&entry->value, entry->offset, sizeof(T)));
    entry->dirty = false;
    return absl::OkStatus();
  }

  // Evicts an entry from the cache and moves the evicted cache node to the
  // front of the LRU list. Returns an error status on failure.
  ASYLO_MUST_USE_RESULT Status Evict() {
    auto last = std::prev(cache_.end());
    ASYLO_RETURN_IF_ERROR(Commit(last));
    index_.erase(last->offset);
    MoveToFront(last);
    return absl::OkStatus();
  }

  // Moves an LRU list node to the front of the list.
  void MoveToFront(ConstNodeRef node) {
    if (node != cache_.begin()) {
      // Splice node onto the front of the list. Note that splice does not
      // invalidate existing iterators into cache_.
      cache_.splice(cache_.begin(), cache_, node);
    }
  }

  size_t capacity_;  // Size of the cache in items of type T.

  // Number of items present in the cache. Although std::list::size() is
  // required to have constant time complexity since C++11, not all library
  // implementions conform to this requirement. In particular, libstdc++
  // versions <= 4.8 implement size() as std::distance(head, tail).
  size_t count_;

  RandomAccessStorage *io_;  // Record backing store.

  // Entries in the cache, maintained in LRU order. This implementation does not
  // preallocate the cache at the time it is created, opting instead to allocate
  // entries and add them to a list lazily as they are referenced. This enables
  // overcommitment of heap capacity at the cost of greater overhead incurred
  // by the default allocator.
  std::list<CacheEntry> cache_;

  absl::flat_hash_map<off_t, ConstNodeRef> index_;  // Index by record offset.
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_UTILS_RECORD_STORE_H_
