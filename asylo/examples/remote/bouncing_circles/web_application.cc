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

#include <cstdlib>
#include <memory>
#include <string>
#include <tuple>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "asylo/examples/remote/bouncing_circles/circle_client.h"
#include "asylo/examples/remote/bouncing_circles/web_server.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/remote/process_main_wrapper.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"

using ::asylo::ProcessMainWrapper;

ABSL_FLAG(int32_t, port, 8888, "Port for the HTML server to listen to");

namespace asylo {
namespace {

constexpr char kPathDefault[] = "/";
constexpr char kPathBouncingCircles[] = "/circles";
constexpr char kPathStart[] = "/start";
constexpr char kPathCalculate[] = "/calc";

constexpr char kResponseDefault[] = R"html(
<!DOCTYPE html>
<html>
<body>
<H2>Parking page</H2>
<P>
  <a  href="/circles">Bouncing circles example</a>
</P>
<canvas id="canvas", width="700", height="500">
</canvas>
</body>
</html>
)html";

constexpr char kResponseCircles[] = R"html(
<!DOCTYPE html>
<html>
<head>
<script type="text/javascript">
var start, update_count;
const formatter2 =
  new Intl.NumberFormat('en-US', { minimumFractionDigits: 2,
                                   maximumFractionDigits: 2 });

function init() {
   update_count = 0;
   start = Date.now();
   const canvas = document.getElementById('canvas');
   var xhttp = new XMLHttpRequest();
   xhttp.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
       setInterval(draw, 1000 / 60, canvas);  // 60 times per second
     }
   };
   xhttp.open('GET',
              '/start' +
              '?width=' + canvas.width +
              '&height=' + canvas.height, true);
   xhttp.send();
}

function draw(canvas) {
  if (!canvas.getContext) return;
  var context = canvas.getContext('2d');
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      var xmlDoc = this.responseXML;
      var circles = xmlDoc.getElementsByTagName("CIRCLE");
      context.clearRect(0, 0, canvas.width, canvas.height);
      const startPoint = (Math.PI/180)*0;
      const endPoint = (Math.PI/180)*360;
      for (circle of circles) {
        var x = Number(circle
            .getElementsByTagName("X")[0].childNodes[0].nodeValue);
        var y = Number(circle
            .getElementsByTagName("Y")[0].childNodes[0].nodeValue);
        var radius = Number(circle
            .getElementsByTagName("RADIUS")[0].childNodes[0].nodeValue);
        context.fillStyle = circle
            .getElementsByTagName("FILL")[0].childNodes[0].nodeValue;
        context.beginPath();
        context.arc(x, y, radius, startPoint, endPoint, true);
        context.fill();
        context.closePath();
      }
      update_count++;
      var millis = Date.now() - start;
      document.getElementById('tps').innerHTML =
        formatter2.format(update_count * 1000 / millis);
      document.getElementById('elapsed').innerHTML =
        formatter2.format(millis/1000);
    }
  };
  // Attach unique parameter to /calc, in order for the browser to not cache it.
  xhttp.open('GET', '/calc?unique_id=' + Math.random(), true);
  xhttp.send();
}
</script>
</head>

<body onload="init();">
<H2>Bouncing Circles</H2>
<P>
  TPS: <a id="tps">0</a>
  Elapsed: <a id="elapsed">0</a> sec
</P>
<canvas id="canvas", width="700", height="500">
</canvas>
<P>
<a href="/">Parking page</a>
</P>
</body>
</html>
)html";

// Handler to emit parking page
WebServer::WebResponse EmitDefault(const WebServer::WebRequest &req) {
  WebServer::WebResponse response;
  if (req.parms.empty()) {
    response.contents = std::string(kResponseDefault);
  }
  return response;
}

// Handler to run bouncing circles
WebServer::WebResponse EmitCircles(const WebServer::WebRequest &req) {
  WebServer::WebResponse response;
  if (req.parms.empty()) {
    response.contents = std::string(kResponseCircles);
  }
  return response;
}

// Handler to initialize circles (internal)
WebServer::WebResponse EmitStart(const WebServer::WebRequest &req) {
  WebServer::WebResponse response;
  if (req.parms.size() == 2 && req.parms.contains("width") &&
      req.parms.contains("height")) {
    auto width = std::stoi(req.parms.find("width")->second);
    auto height = std::stoi(req.parms.find("height")->second);
    CircleStatus::InitializeGlobal(4, /*enclave_prefix=*/"circle_enclave_",
                                   width, height);
  }
  return response;
}

// Handler to asynchronously calculate all circles position (internal)
WebServer::WebResponse EmitCalculate(const WebServer::WebRequest &req) {
  WebServer::WebResponse response;
  response.type = "text/xml";
  response.contents = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CIRCLES>";
  if (req.parms.size() == 1) {  // Unique parameter - ignored.
    const auto circles = CircleStatus::circles();
    if (circles != nullptr) {
      for (auto &c : *circles) {
        int32_t x;
        int32_t y;
        int32_t radius;
        std::string color;
        std::tie(x, y, radius, color) = c->Update();
        absl::StrAppend(&response.contents, "<CIRCLE>");
        absl::StrAppend(&response.contents, "<X>", x, "</X>");
        absl::StrAppend(&response.contents, "<Y>", y, "</Y>");
        absl::StrAppend(&response.contents, "<RADIUS>", radius, "</RADIUS>");
        absl::StrAppend(&response.contents, "<FILL>", color, "</FILL>");
        absl::StrAppend(&response.contents, "</CIRCLE>");
      }
    }
  }
  absl::StrAppend(&response.contents, "</CIRCLES>");
  return response;
}

void RegisterHandlers(WebServer *web_server) {
  web_server->RegisterHandler(kPathDefault, EmitDefault);
  web_server->RegisterHandler(kPathBouncingCircles, EmitCircles);
  web_server->RegisterHandler(kPathStart, EmitStart);
  web_server->RegisterHandler(kPathCalculate, EmitCalculate);
}

}  // namespace

class WebServerImpl {
 public:
  static StatusOr<std::unique_ptr<WebServerImpl>> Create(int port) {
    return absl::WrapUnique(new WebServerImpl(port));
  }

  void Kill(int signum) {
    LOG(ERROR) << "Stop listening to port=" << web_server_->port();
    web_server_->StopServer();
  }

  void Wait() { web_server_->Wait(); }

 private:
  explicit WebServerImpl(int port)
      : web_server_(WebServer::Create(port, /*max_worker_threads=*/16)) {
    RegisterHandlers(web_server_.get());
    web_server_->StartServer();
    LOG(ERROR) << "Start listening to port=" << web_server_->port();
  }

  std::unique_ptr<WebServer> web_server_;
};

}  // namespace asylo

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  const auto run_status =
      ProcessMainWrapper<::asylo::WebServerImpl>::RunUntilTerminated(
          absl::GetFlag(FLAGS_port));
  if (!run_status.ok()) {
    LOG(ERROR) << "Failed to run enclave, status=" << run_status;
    return -1;
  }

  return EXIT_SUCCESS;
}
