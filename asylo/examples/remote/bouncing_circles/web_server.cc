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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

namespace {

#define BUFSIZE 8096

constexpr char kNotFoundMsg[] = R"html(
HTTP/1.1 404 Not Found\n
Content-Length: 136\n
Connection: keep-alive\n
Content-Type: text/html\n
\n
<html><head>\n
<title>404 Not Found</title>\n
</head><body>\n
<h1>Not Found</h1>\n
The requested URL was not found on this server.\n
</body></html>\n
)html";

StatusOr<std::string> ReadRequest(int fd) {
  // Read Web request in one go.
  auto buffer = absl::make_unique<char[]>(BUFSIZE + 1);
  memset(buffer.get(), '\0', BUFSIZE + 1);
  const ssize_t ret = read(fd, buffer.get(), BUFSIZE);
  if (ret < -1) {
    return LastPosixError("Failed to read browser request");
  }
  if (ret == 0) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  "Failed to read browser request"};
  }
  if (ret > BUFSIZE) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  "Browser request too long"};
  }
  // Strip header and extras.
  absl::string_view request(buffer.get(), ret);
  const auto header_pos = request.find(" HTTP/");
  if (header_pos == std::string::npos) {
    return Status{absl::StatusCode::kFailedPrecondition,
                  absl::StrCat("No header found, ", request)};
  }
  request = request.substr(0, header_pos);
  if (!absl::ConsumePrefix(&request, "GET ") &&
      !absl::ConsumePrefix(&request, "get ")) {
    return Status{
        absl::StatusCode::kFailedPrecondition,
        absl::StrCat("Only simple GET operation is supported, ", request)};
  }
  request = absl::StripLeadingAsciiWhitespace(request);
  return std::string(request);
}

WebServer::WebRequest ParseRequest(absl::string_view request) {
  WebServer::WebRequest web_request;
  const auto question_mark_pos = request.find('?');
  if (question_mark_pos != std::string::npos) {
    for (const auto &parameter :
         absl::StrSplit(request.substr(question_mark_pos + 1), '&')) {
      const auto eq_mark_pos = parameter.find('=');
      if (eq_mark_pos == std::string::npos) {
        web_request.parms.emplace(parameter, "");
      } else {
        web_request.parms.emplace(parameter.substr(0, eq_mark_pos),
                                  parameter.substr(eq_mark_pos + 1));
      }
    }
  }
  return web_request;
}

void WriteResponse(int fd, const WebServer::WebResponse &web_result) {
  // Send response back: header and contents.
  std::string raw_response = absl::StrCat(
      "HTTP/1.1 200 OK\n", "Server: ntest/1.0\n",
      "Content-Length: ", web_result.contents.size(), "\n",
      "Connection: keep-alive\n", "Content-Type: ", web_result.type, "\n",
      "\n",  // Additional blank line after header
      web_result.contents);
  CHECK_EQ(write(fd, raw_response.data(), raw_response.size()),
           static_cast<ssize_t>(raw_response.size()));
}

// Internal class for listening thread.
class Listener {
 public:
  explicit Listener(int port)
      : listener_fd_(-1), assigned_port_(-1), listener_cleanup_([this] {
          if (listener_fd_ >= 0) {
            close(listener_fd_);
          }
        }) {
    // Setup the network socket.
    listener_fd_ = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK_GE(listener_fd_, 0) << "Socket failed to create, " << strerror(errno);
    memset(&serv_addr_, 0, sizeof(serv_addr_));
    serv_addr_.sin6_family = AF_INET6;
    serv_addr_.sin6_addr = IN6ADDR_ANY_INIT;
    serv_addr_.sin6_port = htons(port);
    CHECK_GE(
        bind(listener_fd_, reinterpret_cast<struct sockaddr *>(&serv_addr_),
             sizeof(serv_addr_)),
        0)
        << "Failed to bind, " << strerror(errno);
    CHECK_GE(listen(listener_fd_, 64), 0)
        << "Failed to listen, " << strerror(errno);

    // Get my ip address and port
    struct sockaddr_in my_addr;
    memset(&my_addr, 0, sizeof(my_addr));
    socklen_t len = sizeof(my_addr);
    CHECK_EQ(getsockname(listener_fd_,
                         reinterpret_cast<struct sockaddr *>(&my_addr), &len),
             0)
        << "Failed to get socket name, " << strerror(errno);
    assigned_port_ = ntohs(my_addr.sin_port);
    if (port != 0) {
      CHECK_EQ(port, assigned_port_);
    }
  }

  void AcceptRequest(WebServer *server) {
    // Receive request.
    int socket_fd;
    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));
    socklen_t length = sizeof(cli_addr);
    socket_fd = accept(listener_fd_,
                       reinterpret_cast<struct sockaddr *>(&cli_addr), &length);
    // memset(&cli_addr, 0, length);
    if (socket_fd < 0) {
      LOG(ERROR) << "Failed to accept, " << strerror(errno);
      return;
    }
    server->AssignRequest(socket_fd);
  }

  int assigned_port() const { return assigned_port_; }

 private:
  int listener_fd_;
  int assigned_port_;
  Cleanup listener_cleanup_;
  struct sockaddr_in6 serv_addr_;
};

}  // namespace

void WebServer::WorkerThread::WorkerThreadRunner(WebServer *server) {
  for (;;) {
    int fd;
    {
      auto state_lock = state.ReaderLockWhen([](const State &state) {
        return state.must_exit || state.socket_fd >= 0;
      });
      if (state_lock->must_exit) {
        return;
      }
      fd = state_lock->socket_fd;
    }
    Cleanup cleanup([this, fd] {
      if (fd >= 0) close(fd);
      // Indicate that the thread is available for other requests.
      state.Lock()->socket_fd = -1;
    });
    CHECK_GE(fd, 0);
    // Read Web request in one go.
    const auto request_result = ReadRequest(fd);
    if (!request_result.ok()) {
      continue;
    }
    const auto request = request_result.value();

    // Locate handler (if any).
    const auto handler = server->GetHandler(request);
    if (!handler) {
      CHECK_EQ(write(fd, kNotFoundMsg, sizeof(kNotFoundMsg) - 1),
               static_cast<ssize_t>(sizeof(kNotFoundMsg) - 1));
      continue;
    }

    // Parse request and execute handler.
    const auto web_result = handler(ParseRequest(request));

    // Send response back: header and contents.
    WriteResponse(fd, web_result);
  }
}

std::unique_ptr<WebServer> WebServer::Create(int port,
                                             size_t max_worker_threads) {
  return absl::WrapUnique(new WebServer(port, max_worker_threads));
}

WebServer::WebServer(int port, size_t max_worker_threads)
    : port_(port),
      max_worker_threads_(max_worker_threads > 0 ? max_worker_threads : 1),
      start_time_(absl::Now()),
      handlers_(absl::flat_hash_map<std::string, UriHandler>()),
      workers_(std::vector<WorkerThread>(max_worker_threads_)) {}

void WebServer::Wait() {
  std::vector<std::unique_ptr<std::thread>> threads;
  {
    auto lock = workers_.LockWhen([](const std::vector<WorkerThread> &workers) {
      for (auto &worker : workers) {
        if (!worker.state.ReaderLock()->must_exit) {
          return false;
        }
      }
      return true;
    });
    for (auto &worker : *lock) {
      if (worker.thread) {
        threads.emplace_back(std::move(worker.thread));
      }
    }
  }
  for (auto &thread : threads) {
    thread->join();
  }
}

void WebServer::StartServer() {
  MutexGuarded<int> assigned_port(0);
  std::thread listener_thread([this, &assigned_port] {
    // Setup the network socket
    Listener listener(port_);
    *assigned_port.Lock() = listener.assigned_port();
    for (;;) {
      listener.AcceptRequest(this);
    }
  });

  {
    auto lock = assigned_port.ReaderLockWhen([](int port) { return port > 0; });
    port_ = *lock;
  }

  // Detach listener thread and don't care what happens to it later.
  listener_thread.detach();
}

void WebServer::StopServer() {
  auto lock = workers_.Lock();
  for (auto &worker : *lock) {
    worker.state.Lock()->must_exit = true;
  }
}

void WebServer::RegisterHandler(absl::string_view uri_pattern,
                                UriHandler handler) {
  auto locked_handlers = handlers_.Lock();
  CHECK(locked_handlers->emplace(uri_pattern, handler).second);
}

void WebServer::UnregisterHandler(absl::string_view uri_pattern) {
  auto locked_handlers = handlers_.Lock();
  CHECK(locked_handlers->erase(uri_pattern));
}

const WebServer::UriHandler WebServer::GetHandler(
    absl::string_view uri_pattern) const {
  std::string root(uri_pattern.substr(0, uri_pattern.find('?')));
  auto locked_handlers = handlers_.ReaderLock();
  auto it = locked_handlers->find(root);
  if (it == locked_handlers->end()) return nullptr;
  return it->second;
}

void WebServer::AssignRequest(int socket_fd) {
  // Get a lock when there is at least one worker available
  // (store its index in selected_index).
  size_t selected_index = -1;
  auto lock = workers_.LockWhen(
      [this,
       &selected_index](const std::vector<WebServer::WorkerThread> &workers) {
        workers_.AssertReaderHeld();
        for (size_t index = 0; index < workers.size(); ++index) {
          auto state_lock = workers[index].state.ReaderLock();
          if (state_lock->must_exit) {
            continue;  // The thread is flagged to exit.
          }
          if (state_lock->socket_fd < 0) {
            selected_index = index;
            return true;  // Found a worker with no assigned request.
          }
        }
        return false;
      });
  // Start the worker's thread, if not there yet.
  auto &selected_worker = lock->at(selected_index);
  if (!selected_worker.thread) {
    // Create and use the new thread.
    selected_worker.thread = absl::make_unique<std::thread>(
        [this, &selected_worker] { selected_worker.WorkerThreadRunner(this); });
  }
  // Assign the request to the worker we selected.
  auto state_lock = selected_worker.state.Lock();
  state_lock->socket_fd = socket_fd;
}

}  // namespace asylo
