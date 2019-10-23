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

#ifndef ASYLO_EXAMPLES_REMOTE_BOUNCING_CIRCLES_WEB_SERVER_H_
#define ASYLO_EXAMPLES_REMOTE_BOUNCING_CIRCLES_WEB_SERVER_H_

// Based on NWEB.C (see https://github.com/ankushagarwal/nweb)

#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "asylo/util/mutex_guarded.h"

namespace asylo {

// Test web server that can only be used in tests.
// It only serves requests that are registered; does not serve any files.
class WebServer {
 public:
  // In a request '/uri?p1=v1&p2=v2&...' uri determines the handler and
  // everything after '?' is parsed into WebRequest as parms['p1'] = 'v1' etc.
  // If there is no '?', parms is empty.
  struct WebRequest {
    absl::flat_hash_map<std::string, std::string> parms;
  };

  // Response and its type
  struct WebResponse {
    std::string contents;
    std::string type = "text/html";
  };

  // Type used for handler callbacks.
  typedef std::function<WebResponse(const WebRequest &request)> UriHandler;

  // Factory method; the only one allowed to create the server.
  static std::unique_ptr<WebServer> Create(int port, size_t max_worker_threads);

  ~WebServer() = default;

  WebServer(const WebServer &other) = delete;
  WebServer &operator=(const WebServer &other) = delete;

  // Blocks until server stops, returns immediately if server is not running.
  void Wait();

  void StartServer();
  void StopServer();

  void RegisterHandler(absl::string_view uri_pattern, UriHandler handler);
  void UnregisterHandler(absl::string_view uri_pattern);

  // Returns the handler for the given uri. Requires a handler is registered.
  const UriHandler GetHandler(absl::string_view uri_pattern) const;

  // Assign request to an available worker (block if none is available).
  void AssignRequest(int socket_fd);

  // Actually assigned port. Valid only after call to StartServer().
  int port() const { return port_; }

 private:
  // Worker thread.
  struct WorkerThread {
    WorkerThread() : state(State()) {}
    struct State {
      bool must_exit = false;
      int socket_fd = -1;  // Negative if no request is assigned.
    };
    void WorkerThreadRunner(WebServer *server);
    MutexGuarded<State> state;
    std::unique_ptr<std::thread> thread;  // Assigned once, under workers lock.
  };

  // Constructor is private, so that only factory method can create the server.
  WebServer(int port, size_t max_worker_threads);

  // Server status.
  int port_;
  const size_t max_worker_threads_;
  const absl::Time start_time_;

  // Registered request handlers.
  MutexGuarded<absl::flat_hash_map<std::string, UriHandler>> handlers_;

  // Worker threads (no more than max_worker_threads_ at any time).
  MutexGuarded<std::vector<WorkerThread>> workers_;
};

}  //  namespace asylo

#endif  // ASYLO_EXAMPLES_REMOTE_BOUNCING_CIRCLES_WEB_SERVER_H_
