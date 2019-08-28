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

#ifndef ASYLO_PLATFORM_CORE_SHARED_RESOURCE_MANAGER_H_
#define ASYLO_PLATFORM_CORE_SHARED_RESOURCE_MANAGER_H_

#include <memory>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "asylo/platform/core/shared_name.h"
#include "asylo/util/status.h"  // IWYU pragma: export

namespace asylo {

/// A manager object for shared resources.
///
/// A manager object responsible for reference-counted untrusted resources which
/// are shared between trusted and untrusted code.
class SharedResourceManager {
 public:
  /// Registers a shared resource and passes ownership to the
  /// SharedResourceManager.
  ///
  /// Registers a shared resource of type T by name and transfers ownership of
  /// the object to the manager. Managed resources are objects allocated in the
  /// untrusted partition of the application and are addressable by name from
  /// trusted code.
  ///
  /// Each resource is associated with a reference count, which is initialized
  /// to one (1) at the time the resource is registered. Resource counts are
  /// managed explicitly by calls to AcquireResource and ReleaseResource.
  /// Resources are automatically disposed of and removed from the resource
  /// table when their reference count reaches zero (0).
  ///
  /// \param name The name to register to this resource.
  /// \param pointer A pointer to a value that this resource owns and will
  ///                dispose of once it is no longer referenced.
  template <typename T, typename Deleter = std::default_delete<T>>
  Status RegisterManagedResource(const SharedName &name, T *pointer) {
    absl::MutexLock lock(&mu_);
    auto *resource = new ManagedResource<T, Deleter>(name, pointer);
    return InstallResource(resource);
  }

  /// Registers a shared resource owned by that remains owned by the caller.
  ///
  /// Has the same behavior as RegisterManagedResource, except that the
  /// ownership of the resource remains with the caller. This means that that
  /// the resource will not be deleted by the EnclaveManager when its reference
  /// count reaches zero (0). This is appropriate for pointers to objects the
  /// caller owns and would like to make available inside the enclave.
  /// \param name The name to register to this resource.
  /// \param pointer A pointer to a value owned by the caller.
  template <typename T>
  Status RegisterUnmanagedResource(const SharedName &name, T *pointer) {
    absl::MutexLock lock(&mu_);
    auto *resource = new UnmanagedResource<T>(name, pointer);
    return InstallResource(resource);
  }

  /// Acquires a named resource.
  ///
  /// Acquires a named resource by incrementing its reference count and
  /// returning a pointer to an object owned by the EnclaveManager. Returns
  /// nullptr if the named resource does not exist.
  template <typename T>
  T *AcquireResource(const SharedName &name) {
    absl::MutexLock lock(&mu_);
    auto it = shared_resources_.find(name);
    if (it == shared_resources_.end()) {
      return nullptr;
    }
    it->second->reference_count++;
    return static_cast<T *>(it->second->get());
  }

  /// Releases a named resource.
  ///
  /// Releases a named resource by decrementing its reference count. Removes it
  /// from the resource table and delegates finalization to its resource handle
  /// when the reference count reaches zero (0). Returns false if the named
  /// resource does not exist.
  bool ReleaseResource(const SharedName &name);

 private:
  // Implements a handle wrapping a pointer to a shared resource. This is
  // provided to allow different resource types to implement their own cleanup
  // strategy via an appropriate virtual destructor implementation.
  struct ResourceHandle {
    ResourceHandle(const SharedName &name)
        : resource_name(name), reference_count(1) {}
    virtual ~ResourceHandle() = default;

    // Fetches a raw pointer to the managed resource.
    virtual void *get() = 0;

    // Releases the resource from the wrapper. After this call, the lifetime of
    // the resource if no longer managed by the ResourceHandle.
    virtual void release() = 0;

    SharedName resource_name;
    int reference_count;
  };

  // A resource owned by the EnclaveManager.
  template <typename T, typename Deleter>
  struct ManagedResource : public ResourceHandle {
    ManagedResource(const SharedName &name, T *pointer)
        : ResourceHandle(name), resource(pointer) {}
    void *get() override { return static_cast<void *>(resource.get()); }
    void release() override { resource.release(); }
    std::unique_ptr<T, Deleter> resource;
  };

  // A handle for a resource that is not owned by the EnclaveManager.
  template <typename T>
  struct UnmanagedResource : public ResourceHandle {
    UnmanagedResource(const SharedName &name, T *pointer)
        : ResourceHandle(name), resource(pointer) {}
    void *get() override { return static_cast<void *>(resource); }
    void release() override {}
    T *resource;
  };

  // Installs a entry into shared_resources_. Returns failure and deletes the
  // passed resource handle if the provided name is already in use.
  Status InstallResource(ResourceHandle *handle)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

  absl::Mutex mu_;
  absl::flat_hash_map<SharedName, std::unique_ptr<ResourceHandle>,
                      SharedName::Hash, SharedName::Eq>
      shared_resources_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CORE_SHARED_RESOURCE_MANAGER_H_
