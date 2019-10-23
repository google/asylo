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

#include "asylo/examples/remote/bouncing_circles/web_server.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <map>
#include <string>
#include <tuple>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace {

class WebServerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    web_server_ = WebServer::Create(/*port=*/0, /*max_worker_threads=*/1);
    web_server_->StartServer();

    web_client_fd_ = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK_GE(web_client_fd_, 0)
        << "Socket failed to create, " << strerror(errno);

    web_server_addr_.sin6_family = AF_INET6;
    web_server_addr_.sin6_port = htons(web_server_->port());
    web_server_addr_.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    CHECK_GE(connect(web_client_fd_,
                     reinterpret_cast<struct sockaddr *>(&web_server_addr_),
                     sizeof(web_server_addr_)),
             0)
        << "Failed to connect, " << strerror(errno);
  }

  void TearDown() override {
    web_server_->StopServer();
    web_server_->Wait();
  }

  void RegisterHandler(absl::string_view uri_pattern,
                       const WebServer::UriHandler &handler) {
    web_server_->RegisterHandler(uri_pattern, handler);
  }

  // Sends request suffix (something like '/req?a=1&b=2') to the web server,
  // reads back response and parses it, verifying the headers.
  // Returns pair <contents, contents-type> from the web server response.
  std::pair<std::string, std::string> Get(absl::string_view suffix) {
    // Send request.
    std::string request = absl::StrCat("GET ", suffix, " HTTP/1.1");
    ssize_t ret = send(web_client_fd_, request.data(), request.size(), 0);
    CHECK_GE(ret, 0) << "Failed to send request, " << strerror(errno);

    // Get raw response.
    static constexpr size_t kBufSize = 1024;
    auto buffer = absl::make_unique<char[]>(kBufSize);
    memset(buffer.get(), '\0', kBufSize);
    ret = read(web_client_fd_, buffer.get(), kBufSize);
    CHECK_GE(ret, 0) << "Failed to read response, " << strerror(errno);
    CHECK_LT(ret, kBufSize) << "Response too long, " << strerror(errno);
    absl::string_view raw_response(buffer.get(), ret);

    // Retrieve and parse headers.
    auto header_end_pos = raw_response.find("\n\n");
    CHECK_NE(header_end_pos, std::string::npos)
        << "Response has no headers, '" << raw_response << "'";
    absl::flat_hash_map<std::string, std::string> headers;
    for (const auto &h :
         absl::StrSplit(raw_response.substr(0, header_end_pos), '\n')) {
      if (absl::StartsWith(h, "HTTP/")) {
        // There must be OK status at the beginning.
        CHECK_EQ(h, "HTTP/1.1 200 OK") << "Status: '" << h << "'";
        continue;
      }
      auto pos = h.find(": ");
      CHECK_NE(pos, std::string::npos)
          << "Malformed response header, '" << h << "'";
      CHECK(headers.emplace(h.substr(0, pos), h.substr(pos + 1 + 1)).second)
          << "Duplicate header '" << h << "'";
    }
    std::string contents_type = headers.find("Content-Type")->second;
    int64_t contents_length;
    CHECK(absl::SimpleAtoi(headers.find("Content-Length")->second,
                           &contents_length));

    // Retrieve data and compose result.
    auto contents_data =
        raw_response.substr(header_end_pos + 1 + 1, contents_length);
    return {std::string(contents_data), contents_type};
  }

 private:
  std::unique_ptr<WebServer> web_server_;
  struct sockaddr_in6 web_server_addr_;
  int web_client_fd_ = -1;
};

TEST_F(WebServerTest, HtmlTest) {
  constexpr absl::string_view kTestUri("/test");
  constexpr absl::string_view kTestResponse("Hello World!\r\n");

  WebServer::UriHandler handler =
      [&kTestResponse](const WebServer::WebRequest &request) {
        WebServer::WebResponse response;
        response.contents = std::string(kTestResponse);
        return response;
      };

  RegisterHandler(kTestUri, handler);
  auto response = Get(kTestUri);
  EXPECT_THAT(response.first, Eq(kTestResponse));
  EXPECT_THAT(response.second, StrEq("text/html"));
}

TEST_F(WebServerTest, XmlTest) {
  constexpr absl::string_view kTestUri("/test");
  constexpr absl::string_view kTestResponse("Hello World!\r\n");

  WebServer::UriHandler handler =
      [&kTestResponse](const WebServer::WebRequest &request) {
        WebServer::WebResponse response;
        response.contents = std::string(kTestResponse);
        response.type = "text/xml";
        return response;
      };

  RegisterHandler(kTestUri, handler);
  auto response = Get(kTestUri);
  EXPECT_THAT(response.first, Eq(kTestResponse));
  EXPECT_THAT(response.second, StrEq("text/xml"));
}

TEST_F(WebServerTest, HtmlWithParemetersTest) {
  constexpr absl::string_view kTestRoot("/test");
  constexpr absl::string_view kTestUri("/test?x1=s1&x2&=a3&xyz=abc");
  constexpr absl::string_view kTestResponse(".4/:a3/x1:s1/x2:/xyz:abc");

  WebServer::UriHandler handler = [](const WebServer::WebRequest &request) {
    // Make parameters ordered.
    std::map<absl::string_view, absl::string_view> ordered_parms;
    for (const auto &p : request.parms) {
      ordered_parms.emplace(p.first, p.second);
    }
    WebServer::WebResponse response;
    response.contents = absl::StrCat(".", request.parms.size());
    for (const auto &p : ordered_parms) {
      absl::StrAppend(&response.contents, "/", p.first, ":", p.second);
    }
    return response;
  };

  RegisterHandler(kTestRoot, handler);
  auto response = Get(kTestUri);
  EXPECT_THAT(response.first, Eq(kTestResponse));
  EXPECT_THAT(response.second, StrEq("text/html"));
}

}  // namespace
}  // namespace asylo
