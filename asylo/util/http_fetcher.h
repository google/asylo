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
#ifndef ASYLO_UTIL_HTTP_FETCHER_H_
#define ASYLO_UTIL_HTTP_FETCHER_H_

#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Interface for issuing an HTTP(S) GET requests and returning parsed responses.
class HttpFetcher {
 public:
  virtual ~HttpFetcher() {}

  // A key-value pair of strings that represents an HTTP header. For example, an
  // HTTP header "Content-Length: 457" is represented by
  // {"Content-Length", "457"}.
  using HttpHeaderField = std::pair<std::string, std::string>;

  struct HttpResponse {
    int status_code;
    std::vector<HttpHeaderField> header;
    std::string body;

    // Returns the HTTP header value corresponding to |header_key| in the
    // response. Returns absl::nullopt if |header_key| cannot be found in the
    // response.
    absl::optional<std::string> GetHeaderValue(
        absl::string_view header_key) const {
      for (const auto &key_value : header) {
        if (key_value.first == header_key) {
          return key_value.second;
        }
      }
      return absl::nullopt;
    }
  };

  // Fetches |url| through a HTTP(S) GET with custom header fields specified in
  // |custom_headers| and returns an HttpResponse. Returns a non-OK Status if
  // errors arise during fetching. Thread safe. Synchronous.
  virtual StatusOr<HttpResponse> Get(
      absl::string_view url,
      const std::vector<HttpHeaderField> &custom_headers) = 0;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_HTTP_FETCHER_H_
