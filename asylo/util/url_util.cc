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

#include "asylo/util/url_util.h"

#include <memory>

#include "absl/strings/str_cat.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/function_deleter.h"
#include "asylo/util/status.h"
#include <curl/curl.h>

namespace asylo {

StatusOr<std::string> UrlDecode(absl::string_view url) {
  int out_size = 0;
  std::unique_ptr<char[], FunctionDeleter<&curl_free>> result_url(
      curl_easy_unescape(nullptr, url.data(), url.size(), &out_size));
  if (result_url == nullptr) {
    return absl::InternalError(
        absl::StrCat("Decording URL '", url, "', fails"));
  }
  std::string return_str(result_url.get(), out_size);
  return return_str;
}

}  // namespace asylo
