/*
 *
 * Copyright 2020 Asylo authors
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
#ifndef ASYLO_UTIL_HTTP_FETCHER_IMPL_H_
#define ASYLO_UTIL_HTTP_FETCHER_IMPL_H_

#include <memory>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "asylo/util/http_fetcher.h"
#include "asylo/util/statusor.h"
#include <curl/curl.h>

namespace asylo {

// A interface abstracting libcurl functions used by the fetcher.
class Curl {
 public:
  virtual ~Curl() {}

  // Wraps libcurl's curl_easy_setopt call with exactly three arguments.
  virtual Status SetOpt(CURLoption option, void *value) = 0;

  // Wraps libcurl's curl_easy_perform call.
  virtual Status Perform() = 0;

  // Resets the Curl object before each use. Wraps libcurl's curl_easy_init
  // call.
  virtual void Reset() = 0;
};

// Creates an instance of Curl implementation.
std::unique_ptr<Curl> CreateCurl();

// Helper function used by libcurl to parse HTTP headers. See
// https://curl.haxx.se/libcurl/c/CURLOPT_HEADERFUNCTION.html for more details.
// Expose for tests only. Do not use.
size_t ParseHttpHeader(const char *buffer, size_t size, size_t nitems,
                       HttpFetcher::HttpResponse *response);

// Implements HttpFetcher using libcurl.
class HttpFetcherImpl : public HttpFetcher {
 public:
  HttpFetcherImpl() : HttpFetcherImpl("") {}

  // Constructs an HttpFetcherImpl object that will use |ca_cert_filename| as
  // the trusted root for validating the TLS connection with the remote server.
  explicit HttpFetcherImpl(absl::string_view ca_cert_filename)
      : HttpFetcherImpl(CreateCurl(), ca_cert_filename) {}

  explicit HttpFetcherImpl(std::unique_ptr<Curl> curl,
                           absl::string_view ca_cert_filename)
      : curl_(std::move(curl)), ca_cert_filename_(ca_cert_filename) {}
  ~HttpFetcherImpl() override {}

  StatusOr<HttpFetcher::HttpResponse> Get(
      absl::string_view url,
      const std::vector<HttpFetcher::HttpHeaderField> &custom_headers) override;

 private:
  std::unique_ptr<Curl> curl_;
  std::string ca_cert_filename_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_HTTP_FETCHER_IMPL_H_
