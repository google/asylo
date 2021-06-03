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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/core/enclave_manager.h"

namespace asylo {
namespace {

// A fake resource object for testing.
struct TestResource {
  // Initializes the resource with a pointer to write if and when the object is
  // destroyed.
  explicit TestResource(bool *alive) : alive(alive) { *alive = true; }
  ~TestResource() { *alive = false; }
  std::string value;
  bool *alive;
};

TEST(EnclaveResourcesTest, ResourceLifeCycle) {
  const SharedName managed_name(kUnspecifiedName, "managed resource");
  const SharedName unmanaged_name(kUnspecifiedName, "unmanaged resource");

  EnclaveManager::Configure(EnclaveManagerOptions());
  SharedResourceManager *resources =
      EnclaveManager::Instance().value()->shared_resources();

  // Installs a resource with a pointer to a value to set in its destructor.
  bool is_managed_resource_alive;
  bool is_unmanaged_resource_alive;
  TestResource unmanaged_resource(&is_unmanaged_resource_alive);
  auto *managed_resource = new TestResource(&is_managed_resource_alive);
  managed_resource->value = "managed resource";
  unmanaged_resource.value = "unmanaged resource";

  // Register a managed and unmanaged resource.
  resources->RegisterManagedResource(managed_name, managed_resource);
  resources->RegisterUnmanagedResource(unmanaged_name, &unmanaged_resource);

  // Ensure neither object has been destroyed.
  EXPECT_TRUE(is_managed_resource_alive);
  EXPECT_TRUE(is_unmanaged_resource_alive);

  // Ensure we can't register the same name twice.
  EXPECT_FALSE(
      resources->RegisterManagedResource(unmanaged_name, &unmanaged_resource)
          .ok());

  // Run up the resources reference counts.
  for (int i = 0; i < 100; i++) {
    TestResource *resource =
        resources->AcquireResource<TestResource>(unmanaged_name);
    EXPECT_EQ(resource->value, "unmanaged resource");
    resource = resources->AcquireResource<TestResource>(managed_name);
    EXPECT_EQ(resource->value, "managed resource");
  }

  // Ensure that we can release the resource as many times as we acquired it.
  for (int i = 0; i < 100; i++) {
    EXPECT_TRUE(resources->ReleaseResource(managed_name));
    EXPECT_TRUE(is_managed_resource_alive);
    EXPECT_TRUE(resources->ReleaseResource(unmanaged_name));
    EXPECT_TRUE(is_unmanaged_resource_alive);
  }

  // Expect that the managed resource has been deleted after its reference count
  // reaches zero.
  resources->ReleaseResource(managed_name);
  EXPECT_FALSE(is_managed_resource_alive);

  // Expect that the unmanaged resource is still alive after its reference count
  // reaches zero.
  resources->ReleaseResource(unmanaged_name);
  EXPECT_TRUE(is_unmanaged_resource_alive);

  // Expect that releasing a deleted resource fails.
  EXPECT_FALSE(resources->ReleaseResource(managed_name));
  EXPECT_FALSE(resources->ReleaseResource(unmanaged_name));

  // Expect that we can reuse a resource name after it's been destroyed.
  EXPECT_TRUE(
      resources->RegisterManagedResource(unmanaged_name, &unmanaged_resource)
          .ok());
}

TEST(EnclaveResourcesTest, CustomDeleter) {
  EnclaveManager::Configure(EnclaveManagerOptions());
  SharedResourceManager *resources =
      EnclaveManager::Instance().value()->shared_resources();

  // A custom cleanup policy to install for a resource.
  struct CustomCleanupStrategy {
    void operator()(std::string *resource) {
      *resource = "custom cleanup strategy was invoked";
    }
  };

  const SharedName name(kUnspecifiedName, "resource name");
  std::string a_string_resource = "I'm not dead!";
  resources->RegisterManagedResource<std::string, CustomCleanupStrategy>(
      name, &a_string_resource);
  resources->ReleaseResource(name);
  EXPECT_EQ(a_string_resource, "custom cleanup strategy was invoked");
}

}  // namespace
}  // namespace asylo
