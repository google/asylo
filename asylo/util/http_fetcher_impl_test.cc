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

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"
#include <curl/curl.h>

namespace asylo {
namespace {

using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Pair;
using ::testing::ValuesIn;

class FakeCurl : public Curl {
 public:
  static StatusOr<std::unique_ptr<FakeCurl>> Create(
      absl::string_view raw_http_response);

  FakeCurl(const std::vector<std::string> &headers, absl::string_view body)
      : headers_(headers),
        body_(body),
        last_url_(""),
        write_fn_(nullptr),
        write_data_(nullptr),
        header_fn_(nullptr),
        header_data_(nullptr),
        perform_failure_(false) {}
  ~FakeCurl() override {}

  using WriteFn = size_t (*)(const char *, size_t, size_t, void *);

  Status Perform() override;
  Status SetOpt(CURLoption option, void *value) override;
  void Reset() override;
  const std::string last_url() const { return last_url_; }
  const absl::optional<std::string> ca_path() const { return ca_path_; }

  void set_perform_failure() { perform_failure_ = true; }
  void set_setopt_failure(CURLoption option) {
    setopt_failures_.emplace(option);
  }

 private:
  std::vector<std::string> headers_;
  std::string body_;
  std::string last_url_;
  absl::optional<std::string> ca_path_;
  WriteFn write_fn_;
  void *write_data_;
  WriteFn header_fn_;
  void *header_data_;
  bool perform_failure_;
  absl::flat_hash_set<CURLoption> setopt_failures_;
};

StatusOr<std::unique_ptr<FakeCurl>> FakeCurl::Create(
    absl::string_view raw_http_response) {
  std::vector<std::string> lines = absl::StrSplit(raw_http_response, "\r\n");
  if (lines.size() <= 3) {
    return absl::InvalidArgumentError(
        absl::StrCat("HTTP response is malformed: ", raw_http_response));
  }
  std::vector<std::string> headers;
  for (int i = 0; i < lines.size() - 3; ++i) {
    headers.push_back(lines[i] + "\r\n");
  }
  std::string body = lines[lines.size() - 2] + "\r\n";
  return absl::make_unique<FakeCurl>(headers, body);
}

Status FakeCurl::Perform() {
  if (perform_failure_) {
    return absl::InternalError("test");
  }
  for (const auto &header : headers_) {
    (*header_fn_)(header.data(), header.size(), 1, header_data_);
  }
  (*write_fn_)(body_.data(), body_.size(), 1, write_data_);
  return absl::OkStatus();
}

void FakeCurl::Reset() {
  last_url_ = "";
  ca_path_.reset();
  write_fn_ = nullptr;
  write_data_ = nullptr;
  header_fn_ = nullptr;
  header_data_ = nullptr;
}

Status FakeCurl::SetOpt(CURLoption option, void *value) {
  if (setopt_failures_.contains(option)) {
    return absl::InternalError("test");
  }
  switch (option) {
    case CURLOPT_HEADERFUNCTION:
      header_fn_ = reinterpret_cast<WriteFn>(value);
      break;
    case CURLOPT_WRITEFUNCTION:
      write_fn_ = reinterpret_cast<WriteFn>(value);
      break;
    case CURLOPT_HEADERDATA:
      header_data_ = value;
      break;
    case CURLOPT_WRITEDATA:
      write_data_ = value;
      break;
    case CURLOPT_HTTPHEADER:
      break;
    case CURLOPT_URL:
      last_url_ = static_cast<char *>(value);
      break;
    case CURLOPT_CAINFO:
      ca_path_ = static_cast<char *>(value);
      break;
    default:
      return absl::InternalError(absl::StrCat("Unexpected option ", option));
  }
  return absl::OkStatus();
}

TEST(ParseHttpHeaderTest, StatusLine) {
  absl::string_view line = "HTTP/1.1 200 OK\r\n";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Eq(line.size()));
  EXPECT_THAT(response.status_code, Eq(200));
}

TEST(ParseHttpHeaderTest, HeaderLine) {
  absl::string_view line = "Content-Type: text/html; charset=UTF-8\r\n";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Eq(line.size()));
  EXPECT_THAT(response.header.size(), 1);
  EXPECT_THAT(response.GetHeaderValue("Content-Type"),
              "text/html; charset=UTF-8");
}

TEST(ParseHttpHeaderTest, HeaderLine_ExtraTrailingSpace) {
  absl::string_view line = "Content-Type: text/html; charset=UTF-8   \r\n";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Eq(line.size()));
  EXPECT_THAT(response.header.size(), 1);
  EXPECT_THAT(response.GetHeaderValue("Content-Type"),
              "text/html; charset=UTF-8");
}

TEST(ParseHttpHeaderTest, HeaderLine_MoreThanOneColon) {
  absl::string_view line = "A:B:C\r\n";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Eq(line.size()));
  EXPECT_THAT(response.header.size(), 1);
  EXPECT_THAT(response.GetHeaderValue("A"), "B:C");
}

TEST(ParseHttpHeaderTest, EmptyLine) {
  absl::string_view line = "\r\n\r\n";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Eq(line.size()));
  EXPECT_THAT(response.header.size(), 0);
}

TEST(ParseHttpHeaderTest, MalformedLine_NoColon) {
  absl::string_view line = "no colon";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Ne(line.size()));
}

TEST(ParseHttpHeaderTest, MalformedLine_Empty) {
  absl::string_view line = "";
  HttpFetcher::HttpResponse response;
  ASSERT_THAT(ParseHttpHeader(line.data(), 1, line.size(), &response),
              Ne(line.size()));
}

TEST(HttpFetcherImplTest, Success) {
  constexpr char kRawResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "Custom-Header: test\r\n\r\n"
      "<!DOCTYPE html><html><head><title>Bye-bye baby bye-bye</title>"
      "<style>body { background-color: #111 }"
      "h1 { font-size:4cm; text-align: center; color: black;"
      " text-shadow: 0 0 2mm red}</style></head>"
      "<body><h1>Goodbye, world!</h1></body></html>\r\n";
  constexpr char kUrl[] = "http://bye.bye";
  std::unique_ptr<FakeCurl> curl;
  ASYLO_ASSERT_OK_AND_ASSIGN(curl, FakeCurl::Create(kRawResponse));
  FakeCurl *curlptr = curl.get();
  HttpFetcherImpl fetcher(std::move(curl), /*ca_cert_filename=*/"");
  HttpFetcher::HttpResponse response;
  ASYLO_ASSERT_OK_AND_ASSIGN(response, fetcher.Get(kUrl, {}));

  EXPECT_THAT(curlptr->last_url(), Eq(kUrl));
  EXPECT_FALSE(curlptr->ca_path().has_value());
  EXPECT_THAT(response.status_code, 200);
  EXPECT_THAT(response.header,
              ElementsAre(Pair("Content-Type", "text/html; charset=UTF-8"),
                          Pair("Custom-Header", "test")));
  EXPECT_THAT(
      response.body,
      Eq("<!DOCTYPE html><html><head><title>Bye-bye baby bye-bye</title>"
         "<style>body { background-color: #111 }"
         "h1 { font-size:4cm; text-align: center; color: black;"
         " text-shadow: 0 0 2mm red}</style></head>"
         "<body><h1>Goodbye, world!</h1></body></html>\r\n"));
}

TEST(HttpFetcherImplTest, ExplicitCaPathConstructor) {
  constexpr char kCaPath[] = "/path/to/ca/file";
  constexpr char kRawResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "\r\n"
      "lorem ipsum dolor sit\r\n";
  std::unique_ptr<FakeCurl> curl;
  ASYLO_ASSERT_OK_AND_ASSIGN(curl, FakeCurl::Create(kRawResponse));
  FakeCurl *curlptr = curl.get();
  HttpFetcherImpl fetcher(std::move(curl), kCaPath);
  HttpFetcher::HttpResponse response;
  ASYLO_ASSERT_OK_AND_ASSIGN(response, fetcher.Get("http://lorem.ipsum", {}));

  ASSERT_TRUE(curlptr->ca_path().has_value());
  EXPECT_THAT(curlptr->ca_path().value(), Eq(kCaPath));
  EXPECT_THAT(response.status_code, 200);
  EXPECT_THAT(response.body, Eq("lorem ipsum dolor sit\r\n"));
}

TEST(HttpFetcherImplTest, Perform_Failure) {
  constexpr char kRawResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "Custom-Header: test\r\n\r\n"
      "<!DOCTYPE html><html><head><title>Bye-bye baby bye-bye</title>"
      "<style>body { background-color: #111 }"
      "h1 { font-size:4cm; text-align: center; color: black;"
      " text-shadow: 0 0 2mm red}</style></head>"
      "<body><h1>Goodbye, world!</h1></body></html>\r\n";
  constexpr char kUrl[] = "http://bye.bye";
  std::unique_ptr<FakeCurl> curl;
  ASYLO_ASSERT_OK_AND_ASSIGN(curl, FakeCurl::Create(kRawResponse));
  curl->set_perform_failure();
  HttpFetcherImpl fetcher(std::move(curl), /*ca_cert_filename=*/"");
  HttpFetcher::HttpResponse response;
  EXPECT_THAT(fetcher.Get(kUrl, {}), StatusIs(absl::StatusCode::kInternal));
}

class HttpFetcherImplSetOptErrorTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<CURLoption> {};

// These tests represents the situation where SetOpt from Curl returns an error.
INSTANTIATE_TEST_SUITE_P(SetOptErrors, HttpFetcherImplSetOptErrorTest,
                         ValuesIn(std::vector<CURLoption>{
                             CURLOPT_URL, CURLOPT_HEADERFUNCTION,
                             CURLOPT_HEADERDATA, CURLOPT_WRITEFUNCTION,
                             CURLOPT_WRITEDATA, CURLOPT_CAINFO}));

TEST_P(HttpFetcherImplSetOptErrorTest, SetOpt_Failure) {
  constexpr char kRawResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "Custom-Header: test\r\n\r\n"
      "<!DOCTYPE html><html><head><title>Bye-bye baby bye-bye</title>"
      "<style>body { background-color: #111 }"
      "h1 { font-size:4cm; text-align: center; color: black;"
      " text-shadow: 0 0 2mm red}</style></head>"
      "<body><h1>Goodbye, world!</h1></body></html>\r\n";
  constexpr char kUrl[] = "http://bye.bye";
  std::unique_ptr<FakeCurl> curl;
  ASYLO_ASSERT_OK_AND_ASSIGN(curl, FakeCurl::Create(kRawResponse));
  curl->set_setopt_failure(GetParam());
  HttpFetcherImpl fetcher(std::move(curl), "/ca/cert/filename");
  HttpFetcher::HttpResponse response;
  EXPECT_THAT(fetcher.Get(kUrl, {}), StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace asylo
