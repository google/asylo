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

#include <cstdint>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/examples/remote/bouncing_circles/circles.pb.h"
#include "asylo/util/logging.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

class CircleStatus {
 public:
  CircleStatus(int32_t width, int32_t height)
      : width_(width),
        height_(height),
        x_(std::min((CENTER_X) < 0 ? width + (CENTER_X) : (CENTER_X), width)),
        y_(std::min((CENTER_Y) < 0 ? height + (CENTER_Y) : (CENTER_Y), height)),
        radius_(std::max(2, (CIRCLE_RADIUS))),
        color_(CIRCLE_COLOR) {}

  void Update() {
    if (x_ <= width_ / 10) {
      step_x_ = +(SPEED_X);
    } else if (x_ >= width_ * 9 / 10) {
      step_x_ = -(SPEED_X);
    }
    if (y_ <= height_ / 10) {
      step_y_ = +(SPEED_Y);
    } else if (y_ >= height_ * 9 / 10) {
      step_y_ = -(SPEED_Y);
    }
    x_ += step_x_;
    y_ += step_y_;
    if (radius_ <= 10) {
      step_radius_ = +2;
    } else if (radius_ >= 50) {
      step_radius_ = -2;
    }
    radius_ += step_radius_;
  }

  int32_t width() const { return width_; }
  int32_t height() const { return height_; }
  int32_t x() const { return x_; }
  int32_t y() const { return y_; }
  int32_t radius() const { return radius_; }
  std::string color() const { return color_; }

 private:
  const int32_t width_;
  const int32_t height_;

  int32_t x_;
  int32_t y_;
  int32_t radius_;
  std::string color_;

  int32_t step_x_ = (SPEED_X);
  int32_t step_y_ = (SPEED_Y);
  int32_t step_radius_ = 10;
};

class CirclesEnclave : public TrustedApplication {
 public:
  CirclesEnclave() = default;

  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override {
    if (input.HasExtension(bouncing_circles::enclave_setup_input)) {
      // Output attached and left empty.
      output->MutableExtension(bouncing_circles::enclave_setup_output);
      return HandleSetup(
          input.GetExtension(bouncing_circles::enclave_setup_input));
    }

    if (input.HasExtension(bouncing_circles::enclave_update_position_input)) {
      // Input unused.
      return HandleUpdate(output->MutableExtension(
          bouncing_circles::enclave_update_position_output));
    }

    return absl::InvalidArgumentError("Missing extension on EnclaveInput.");
  }

 private:
  Status HandleSetup(const bouncing_circles::CirclesSetupInput &input) {
    if (input.height() >= input.width()) {
      return absl::FailedPreconditionError(
          absl::StrCat("Height=", input.height(), " weight=", input.width()));
    }
    if (managed_circle_) {
      return absl::AlreadyExistsError("Circle already created");
    }
    managed_circle_ =
        absl::make_unique<CircleStatus>(input.width(), input.height());
    return absl::OkStatus();
  }

  Status HandleUpdate(bouncing_circles::CirclesUpdatePositionOutput *output) {
    if (!managed_circle_) {
      return absl::NotFoundError("Calling Update before Setup");
    }
    managed_circle_->Update();
    output->set_x(managed_circle_->x());
    output->set_y(managed_circle_->y());
    output->set_radius(managed_circle_->radius());
    output->set_color(managed_circle_->color());
    return absl::OkStatus();
  }

  std::unique_ptr<CircleStatus> managed_circle_;
};

}  // namespace

TrustedApplication *BuildTrustedApplication() { return new CirclesEnclave(); }

}  // namespace asylo
