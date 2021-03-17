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
#include "asylo/util/http_fetcher_impl.h"

#include <cstddef>
#include <cstring>

#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/function_deleter.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include <curl/curl.h>
#include <curl/easy.h>
#include "re2/re2.h"

namespace asylo {
namespace {

const LazyRE2 kHttpResponseStatusLineRegexp = {"^HTTP[^ ]* *(\\d+)[^\\d]*\r\n"};

size_t ReadToString(const char *buffer, size_t size, size_t nitems,
                    std::string *stream) {
  stream->append(buffer, size * nitems);
  return size * nitems;
}

bool IsSpaceOrCntrl(char c) { return c <= ' '; }

// Helper function when reading response headers that strips off trailing \r\n.
void StripWhitespaceAndCtrl(std::string *str) {
  int len = static_cast<int>(str->size());
  const char *data = str->data();
  while (len > 0 && IsSpaceOrCntrl(data[len - 1])) {
    --len;
  }
  int offset = 0;
  for (; offset < len && IsSpaceOrCntrl(data[offset]); ++offset) {
  }
  *str = std::string(data + offset, len - offset);
}

bool FindHttpStatus(const std::string &header, int *http_code) {
  return RE2::FullMatch(header, *kHttpResponseStatusLineRegexp, http_code);
}

void CurlCleanup(void *curl) {
  curl_easy_cleanup(reinterpret_cast<CURL *>(curl));
}

class CurlImpl : public Curl {
 public:
  CurlImpl() : curl_(nullptr) { Reset(); }
  ~CurlImpl() override {}

  Status SetOpt(CURLoption option, void *value) override {
    return ToStatus(curl_easy_setopt(curl_.get(), option, value));
  }

  Status Perform() override { return ToStatus(curl_easy_perform(curl_.get())); }

  void Reset() override {
    curl_.reset(curl_easy_init());
    memset(err_msg_, 0, sizeof(err_msg_));
    ASYLO_CHECK_OK(SetOpt(CURLOPT_ERRORBUFFER, err_msg_));
  }

  // Not copyable or movable.
  CurlImpl(const CurlImpl &) = delete;
  CurlImpl &operator=(const CurlImpl &) = delete;
  CurlImpl(CurlImpl &&) = delete;
  CurlImpl &operator=(CurlImpl &&) = delete;

 private:
  // Return a Status based on |error_code|. Populate error message from
  // |err_msg_|.
  Status ToStatus(CURLcode error_code) {
    if (error_code == CURLE_OK) {
      return absl::OkStatus();
    }
    return Status(absl::StatusCode::kInternal,
                  absl::StrFormat(
                      "Call to libcurl failed with error code %s and msg '%s'",
                      curl_easy_strerror(error_code), err_msg_));
  }

  std::unique_ptr<CURL, FunctionDeleter<CurlCleanup>> curl_;
  char err_msg_[CURL_ERROR_SIZE];
};

void FreeCurlList(void *headers) {
  curl_slist_free_all(reinterpret_cast<curl_slist *>(headers));
}

}  // namespace

std::unique_ptr<Curl> CreateCurl() { return absl::make_unique<CurlImpl>(); }

size_t ParseHttpHeader(const char *buffer, size_t size, size_t nitems,
                       HttpFetcher::HttpResponse *response) {
  if (nitems == 0) {
    // Return any size that is different from |nitems| to signal error.
    return 1;
  }
  const size_t data_len = size * nitems;
  int http_code = 0;
  std::string header(buffer, data_len);
  if (FindHttpStatus(header, &http_code)) {
    response->status_code = http_code;
  } else {
    StripWhitespaceAndCtrl(&header);  // remove whitespace and trailing \r\n
    if (header.empty()) {
      return data_len;
    }
    auto colon = header.find(':');
    // Return error if we did not find a ":".
    if (colon == std::string::npos) {
      return 0;
    }
    absl::string_view value = absl::ClippedSubstr(header, colon + 1);
    value = absl::StripAsciiWhitespace(value);
    response->header.push_back(std::make_pair(
        std::string(header.substr(0, colon)), std::string(value)));
  }
  return data_len;
}

StatusOr<HttpFetcher::HttpResponse> HttpFetcherImpl::Get(
    absl::string_view url,
    const std::vector<HttpFetcher::HttpHeaderField> &custom_headers) {
  curl_->Reset();
  if (!ca_cert_filename_.empty()) {
    ASYLO_RETURN_IF_ERROR(curl_->SetOpt(
        CURLOPT_CAINFO, const_cast<char *>(ca_cert_filename_.c_str())));
  }
  ASYLO_RETURN_IF_ERROR(curl_->SetOpt(
      CURLOPT_URL,
      reinterpret_cast<void *>(const_cast<char *>(std::string(url).c_str()))));
  std::unique_ptr<curl_slist, FunctionDeleter<FreeCurlList>> headers;
  for (const auto &header : custom_headers) {
    headers.reset(curl_slist_append(
        headers.get(),
        absl::StrFormat("%s: %s", header.first, header.second).c_str()));
  }
  ASYLO_RETURN_IF_ERROR(curl_->SetOpt(CURLOPT_HTTPHEADER, headers.get()));
  HttpFetcher::HttpResponse result;
  ASYLO_RETURN_IF_ERROR(curl_->SetOpt(CURLOPT_WRITEFUNCTION,
                                      reinterpret_cast<void *>(ReadToString)));
  ASYLO_RETURN_IF_ERROR(curl_->SetOpt(CURLOPT_WRITEDATA, &result.body));
  ASYLO_RETURN_IF_ERROR(curl_->SetOpt(CURLOPT_HEADERDATA, &result));
  ASYLO_RETURN_IF_ERROR(curl_->SetOpt(
      CURLOPT_HEADERFUNCTION, reinterpret_cast<void *>(ParseHttpHeader)));
  ASYLO_RETURN_IF_ERROR(curl_->Perform());
  return result;
}

}  // namespace asylo
