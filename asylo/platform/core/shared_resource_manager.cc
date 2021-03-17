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

#include "asylo/platform/core/shared_resource_manager.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"

namespace asylo {

Status SharedResourceManager::InstallResource(ResourceHandle *handle) {
  mu_.AssertHeld();
  auto it = shared_resources_.find(handle->resource_name);
  if (it != shared_resources_.end()) {
    // If we're not able to insert the resource, destroy the handle wrapper but
    // do not destroy the wrapped resource.
    std::string name = handle->resource_name.name();
    handle->release();
    delete handle;
    return absl::AlreadyExistsError(absl::StrCat(
        "Cannot install resource \"", name, "\": Resource already exists."));
  }
  shared_resources_[handle->resource_name] = absl::WrapUnique(handle);
  return absl::OkStatus();
}

bool SharedResourceManager::ReleaseResource(const SharedName &name) {
  absl::MutexLock lock(&mu_);
  auto it = shared_resources_.find(name);
  if (it == shared_resources_.end()) {
    return false;
  }
  it->second->reference_count--;
  if (it->second->reference_count == 0) {
    shared_resources_.erase(it);
  }
  return true;
}

}  // namespace asylo
