/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/platform/primitives/remote/communicator.h"

#include <cxxabi.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iterator>
#include <memory>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/container/flat_hash_set.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/blocking_counter.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"
#include "opencensus/stats/stats.h"
#include "opencensus/tags/tag_key.h"

using ::opencensus::stats::ViewData;
using ::opencensus::stats::ViewDescriptor;
using ::testing::Eq;
using ::testing::Field;
using ::testing::InSequence;
using ::testing::IsEmpty;
using ::testing::Lt;
using ::testing::MockFunction;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Pointee;
using ::testing::RegisterTest;
using ::testing::SizeIs;

namespace asylo {
namespace primitives {
namespace test {

// Base class for test instances.
class CommunicatorTestFixture : public ::testing::Test {
 public:
  // Forks process. Must be called once and only once, after all tests (derived
  // from CommunicatorTestFixture) have been constructed and registered.
  static void ForkProcess() {
    CHECK_EQ(child_pid_, 0) << "ForkProcess may not be called more than once";
    child_pid_ = fork();
    CHECK_GE(child_pid_, 0) << strerror(errno);
  }

  // Finishes test suite execution, exiting child (target) process and
  // waiting for it to terminate on the parent (host) side.
  static void TearDownTestSuite() {
    // Once, after all tests have finished.
    if (child_pid_ == 0) {
      // Child process exits, using '_exit' rather than 'exit'.
      _exit(0);
    }
    // On parent, wait for the child to exit.
    int wstatus;
    waitpid(child_pid_, &wstatus, 0);
    CHECK_EQ(0, wstatus);
  }

  template <typename Test>
  static void Register() {
    auto test = new Test();
    int status = 0;
    size_t length = 0;
    auto demangled =
        abi::__cxa_demangle(typeid(*test).name(), nullptr, &length, &status);
    Cleanup clean_up([demangled] { free(demangled); });
    const auto test_name = (status == 0 && demangled != nullptr)
                               ? demangled  // Demangling succeeded.
                               : typeid(*test).name();
    RegisterTest("CommunicatorTestFixture", test_name, nullptr, nullptr,
                 __FILE__, __LINE__,
                 // Important to use the fixture type as the return type here.
                 [test]() -> CommunicatorTestFixture * { return test; });
  }

 protected:
  using ServerHandlerMock =
      MockFunction<void(std::unique_ptr<Communicator::Invocation> invocation)>;

  CommunicatorTestFixture() {
    // Create socket pair to communicate server ports between host and target.
    auto res = socketpair(AF_UNIX, SOCK_STREAM, 0, fds_);
    CHECK_EQ(res, 0) << strerror(errno);
  }

 private:
  // Sets up host-side handler expectations, defaults to not being called
  // unless overridden.
  virtual void SetHostHandler(ServerHandlerMock *handler,
                              Communicator *communicator) {
    EXPECT_CALL(*handler, Call(NotNull())).Times(0);
  }

  // Sets up target-side handler expectations, defaults to not being called
  // unless overridden.
  virtual void SetTargetHandler(ServerHandlerMock *handler,
                                Communicator *communicator) {
    EXPECT_CALL(*handler, Call(NotNull())).Times(0);
  }

  // Sets up handler expectations; makes sense to be overridden,
  // if the expectations are identical for both.
  virtual void SetHandler(ServerHandlerMock *handler,
                          Communicator *communicator) {
    if (communicator->is_host()) {
      SetHostHandler(handler, communicator);
    } else {
      SetTargetHandler(handler, communicator);
    }
  }

  // Runs host-side action. Must be overridden.
  virtual void RunAction(Communicator *communicator) = 0;

  // Runs the host or target side of the test, expecting fds_ socketpair
  // to be set for the cross-process communication.
  // Creates Communicator, starts its server, exchanges ports with counterpart,
  // connects to the counterpart.
  void TestBody() final {
    auto communicator = absl::make_unique<Communicator>(
        /*is_host=*/(child_pid_ != 0));

    // Close unused socket.
    ASSERT_THAT(close(fds_[communicator->is_host() ? 1 : 0]), Eq(0))
        << strerror(errno);
    fds_[communicator->is_host() ? 1 : 0] = -1;

    std::unique_ptr<RemoteProxyConnectionConfig> connection_config;
    ASYLO_ASSERT_OK_AND_ASSIGN(connection_config,
                               RemoteProxyConnectionConfig::Defaults());

    // Start server.
    ASYLO_ASSERT_OK(
        communicator->StartServer(connection_config->server_creds()));

    if (communicator->is_host()) {
      // For host: Communicate server port to the target Communicator.
      int server_port = communicator->server_port();
      ASSERT_THAT(write(fds_[0], &server_port, sizeof(server_port)),
                  Eq(sizeof(server_port)))
          << strerror(errno);

      // Wait for the endpoint address back.
      auto end_point = communicator->WaitForEndPointAddress();

      std::unique_ptr<RemoteProxyClientConfig> proxy_config;
      ASYLO_ASSERT_OK_AND_ASSIGN(proxy_config,
                                 RemoteProxyClientConfig::DefaultsWithProvision(
                                     RemoteProvision::Instantiate()));
      proxy_config->EnableOpenCensusMetricsCollection(absl::Seconds(1),
                                                      "test_name");

      // Establish connection to the target server.
      ASYLO_ASSERT_OK(communicator->Connect(*proxy_config, end_point));
    } else {
      // For target: receive host server port.
      int host_server_port = 0;
      ASSERT_THAT(read(fds_[1], &host_server_port, sizeof(host_server_port)),
                  Eq(sizeof(host_server_port)))
          << strerror(errno);

      RemoteProxyConfig proxy_config(std::move(connection_config));

      // Establish connection to the host server.
      ASYLO_ASSERT_OK(communicator->Connect(
          proxy_config, absl::StrCat("[::]:", host_server_port)));

      // Communicate end point to the host.
      communicator->SendEndPointAddress(
          absl::StrCat("[::]:", communicator->server_port()));
    }

    // Close remaining socket.
    ASSERT_THAT(close(fds_[communicator->is_host() ? 0 : 1]), Eq(0))
        << strerror(errno);
    fds_[communicator->is_host() ? 0 : 1] = -1;

    // Set up handler.
    ServerHandlerMock handler;
    SetHandler(&handler, communicator.get());
    communicator->set_handler(handler.AsStdFunction());

    if (!communicator->is_host()) {
      // Target side runs processing loop on main thread until it exits.
      communicator->ServerRpcLoop();
      return;
    }

    // Host runs the action.
    RunAction(communicator.get());
  }

  int fds_[2] = {-1, -1};

  static pid_t child_pid_;
};

pid_t CommunicatorTestFixture::child_pid_ = 0;

class NoInvokesTest : public CommunicatorTestFixture {
 public:
  NoInvokesTest() = default;

 private:
  void RunAction(Communicator *communicator) override {
    // Do nothing, just sleep to give time to establish connection.
    absl::SleepFor(absl::Seconds(1));
  }
};

class SingleInvokeTest : public CommunicatorTestFixture {
 public:
  SingleInvokeTest() = default;

 private:
  const uint64_t kSelector = 1234;
  const absl::string_view kTargetTag = "Target";
  const absl::string_view kHostTag = "Host";
  const uint64_t kTestValue = 12345;

  void SetTargetHandler(ServerHandlerMock *handler,
                        Communicator *communicator) override {
    EXPECT_CALL(*handler, Call(NotNull()))
        .WillOnce([this](std::unique_ptr<Communicator::Invocation> invocation) {
          ASYLO_ASSERT_OK(invocation->status);
          // Consume input.
          ASSERT_THAT(invocation->reader, SizeIs(2));
          const auto tag = invocation->reader.next();
          ASSERT_THAT(tag, SizeIs(kHostTag.size()));
          ASSERT_THAT(memcmp(tag.data(), kHostTag.data(), tag.size()), Eq(0));
          const auto value = invocation->reader.next<uint64_t>();
          // Produce output.
          invocation->writer.PushByCopy({kTargetTag.data(), kTargetTag.size()});
          invocation->writer.Push(value);
        });
  }

  void RunAction(Communicator *communicator) override {
    const auto current_thread_id = Thread::this_thread_id();
    communicator->Invoke(
        kSelector,
        [this](Communicator::Invocation *invocation) {
          invocation->writer.PushByCopy({kHostTag.data(), kHostTag.size()});
          invocation->writer.Push(kTestValue);
        },
        [this, current_thread_id](
            std::unique_ptr<Communicator::Invocation> invocation) {
          ASYLO_ASSERT_OK(invocation->status);
          ASSERT_THAT(invocation->invocation_thread_id, Eq(current_thread_id));
          // Consume input.
          ASSERT_THAT(invocation->reader, SizeIs(2));
          const auto tag = invocation->reader.next();
          ASSERT_THAT(tag, SizeIs(kTargetTag.size()));
          ASSERT_THAT(memcmp(tag.data(), kTargetTag.data(), tag.size()), Eq(0));
          const auto value = invocation->reader.next<uint64_t>();
          EXPECT_THAT(value, Eq(kTestValue));
          // Produce no result.
        });
  }
};

class InvokeAndCountTest : public CommunicatorTestFixture {
 public:
  InvokeAndCountTest() = default;

 private:
  const uint64_t kSelector = 1234;
  const int64_t kTotalMessages = 100;

  void SetTargetHandler(ServerHandlerMock *handler,
                        Communicator *communicator) override {
    EXPECT_CALL(*handler, Call(NotNull()))
        .Times(kTotalMessages)
        .WillRepeatedly(
            [](std::unique_ptr<Communicator::Invocation> invocation) {
              ASYLO_ASSERT_OK(invocation->status);
              // Make output identical to input.
              while (invocation->reader.hasNext()) {
                invocation->writer.PushByCopy(invocation->reader.next());
              }
            });
  }

  void RunAction(Communicator *communicator) override {
    absl::BlockingCounter send_count(kTotalMessages);
    for (int64_t i = 0; i < kTotalMessages; ++i) {
      const auto current_thread_id = Thread::this_thread_id();
      communicator->Invoke(
          kSelector,
          [&i](Communicator::Invocation *invocation) {
            invocation->writer.Push(i);
          },
          [i, &send_count, current_thread_id](
              std::unique_ptr<Communicator::Invocation> invocation) {
            ASYLO_ASSERT_OK(invocation->status);
            ASSERT_THAT(invocation->invocation_thread_id,
                        Eq(current_thread_id));
            ASSERT_THAT(invocation->reader, SizeIs(1));
            EXPECT_THAT(invocation->reader.next<int64_t>(), Eq(i));
            send_count.DecrementCount();
          });
    }
    send_count.Wait();
  }
};

class MultithreadedInvokesAndCheckBackTest : public CommunicatorTestFixture {
 public:
  MultithreadedInvokesAndCheckBackTest()
      : thread_set_((absl::flat_hash_set<std::thread::id>())),
        values_((std::set<int64_t>())) {}

 private:
  const uint64_t kDataSelector = 1234;
  const uint64_t kCountSelector = 4321;
  const int64_t kThreads = 64;
  const int64_t kTotalMessages = 256;

  void SetTargetHandler(ServerHandlerMock *handler,
                        Communicator *communicator) override {
    {
      InSequence seq;
      EXPECT_CALL(*handler, Call(NotNull()))
          .Times(kThreads * kTotalMessages)
          .WillRepeatedly([this](std::unique_ptr<Communicator::Invocation>
                                     invocation) {
            ASSERT_THAT(invocation->selector, Eq(kDataSelector));
            // Make sure the thread is in the set.
            if (thread_set_.Lock()->insert(std::this_thread::get_id()).second) {
              // Thread id has just been added to the set.
              thread_local Cleanup ThreadExit([this] {
                // Thread id removal callback.
                thread_set_.Lock()->erase(std::this_thread::get_id());
              });
            }
            // Regardless of whether the thread is seen for the first
            // time or not, total number of threads is already > 0.
            ASSERT_THAT(*thread_set_.ReaderLock(), Not(IsEmpty()));
            // Consume input.
            ASSERT_THAT(invocation->reader, SizeIs(1));
            const int64_t number = invocation->reader.next<int64_t>();
            ASSERT_THAT(number, Lt(kThreads * kTotalMessages));
            ASSERT_TRUE(values_.Lock()->insert(number).second) << number;
            // Produce no output.
          })
          .RetiresOnSaturation();
      EXPECT_CALL(*handler, Call(NotNull()))
          .WillOnce([this](
                        std::unique_ptr<Communicator::Invocation> invocation) {
            // Final message.
            ASSERT_THAT(invocation->selector, Eq(kCountSelector));
            // No input.
            ASSERT_THAT(invocation->reader, IsEmpty());
            // All threads expected to be gone.
            ASSERT_THAT(*thread_set_.ReaderLock(), IsEmpty());
            // Count collected values. Produce output.
            auto locked_values = values_.ReaderLock();
            ASSERT_THAT(*locked_values, Not(IsEmpty()));
            ASSERT_THAT(*locked_values->begin(), 0);
            ASSERT_THAT(*locked_values->rbegin() + 1,
                        Eq(kThreads * kTotalMessages));
            ASSERT_THAT(locked_values->size(), Eq(kThreads * kTotalMessages));
            invocation->writer.Push<int64_t>(locked_values->size());
          });
    }
  }

  void RunAction(Communicator *communicator) override {
    // There is no direct way to count threads, so instead keep a set of
    // thread ids that have been seen. When a kDataSelector message is
    // received by a thread, its thread id is added to the thread_set. When
    // a thread exits, thread-local at_exit callback removes the thread id
    // from thread_set. By the time kNumThreadsSelector request is sent, all
    // thread ids are expected to be gone from the set.

    // Run multiple writes in parallel. Each will send kTotalMessages with
    // unique contents.
    std::vector<Thread> threads;
    for (int64_t thread_index = 0; thread_index < kThreads; ++thread_index) {
      threads.emplace_back([this, communicator, thread_index] {
        for (int64_t i = 0; i < kTotalMessages; ++i) {
          const auto current_thread_id = Thread::this_thread_id();
          communicator->Invoke(
              kDataSelector,
              [this, thread_index, i](Communicator::Invocation *invocation) {
                invocation->writer.Push(thread_index * kTotalMessages + i);
              },
              [current_thread_id](
                  std::unique_ptr<Communicator::Invocation> invocation) {
                ASYLO_ASSERT_OK(invocation->status);
                ASSERT_THAT(invocation->invocation_thread_id,
                            Eq(current_thread_id));
                ASSERT_THAT(invocation->reader, IsEmpty());
              });
        }
      });
    }
    // Wait for all threads to join.
    for (auto &thread : threads) {
      thread.Join();
    }
    threads.clear();

    // Send count request after all threads are done.
    communicator->Invoke(
        kCountSelector,
        [](Communicator::Invocation *invocation) {
          // No input.
        },
        [this](std::unique_ptr<Communicator::Invocation> invocation) {
          ASSERT_THAT(invocation->reader, SizeIs(1));
          const int64_t total_number = invocation->reader.next<int64_t>();
          EXPECT_THAT(total_number, Eq(kTotalMessages * kThreads));
        });
  }

  MutexGuarded<absl::flat_hash_set<std::thread::id>> thread_set_;
  MutexGuarded<std::set<int64_t>> values_;
};

class MultithreadedWithThreadLocalStorageTest : public CommunicatorTestFixture {
 public:
  MultithreadedWithThreadLocalStorageTest() = default;

 private:
  const uint64_t kDataSelector = 1234;
  const uint64_t kSumSelector = 4321;
  const int64_t kThreads = 64;
  const int64_t kTotalMessages = 256;

  void SetTargetHandler(ServerHandlerMock *handler,
                        Communicator *communicator) override {
    EXPECT_CALL(*handler,
                Call(Pointee(Field(&Communicator::Invocation::selector,
                                   Eq(kDataSelector)))))
        .Times(kThreads * kTotalMessages)
        .WillRepeatedly(
            [this](std::unique_ptr<Communicator::Invocation> invocation) {
              // Consume input.
              ASSERT_THAT(invocation->reader, SizeIs(1));
              const int64_t number = invocation->reader.next<int64_t>();
              ASSERT_THAT(number, Lt(kThreads * kTotalMessages));
              // Per-thread sum of the numbers.
              thread_sum_ += number;
              // Produce no output.
            })
        .RetiresOnSaturation();
    EXPECT_CALL(*handler,
                Call(Pointee(Field(&Communicator::Invocation::selector,
                                   Eq(kSumSelector)))))
        .Times(kThreads)
        .WillRepeatedly(
            [](std::unique_ptr<Communicator::Invocation> invocation) {
              // Final message for a thread has no input.
              ASSERT_THAT(invocation->reader, IsEmpty());
              // Return sum of all received numbers for this thread.
              invocation->writer.Push(thread_sum_);
            });
  }

  void RunAction(Communicator *communicator) override {
    // Run multiple threads in parallel. Each thread will send kTotalMessages
    // with numbers forming an arithmetic progression: [thread_index *
    // kTotalMessages + 0,
    //  thread_index * kTotalMessages + (kTotalMessages - 1)]
    // At the end each thread will request to get sum of all these numbers.
    std::vector<Thread> threads;
    for (int64_t thread_index = 0; thread_index < kThreads; ++thread_index) {
      threads.emplace_back([this, communicator, thread_index] {
        const auto current_thread_id = Thread::this_thread_id();
        for (int64_t i = 0; i < kTotalMessages; ++i) {
          communicator->Invoke(
              kDataSelector,
              [this, thread_index, i](Communicator::Invocation *invocation) {
                invocation->writer.Push(thread_index * kTotalMessages + i);
              },
              [current_thread_id](
                  std::unique_ptr<Communicator::Invocation> invocation) {
                ASYLO_ASSERT_OK(invocation->status);
                ASSERT_THAT(invocation->invocation_thread_id,
                            Eq(current_thread_id));
                ASSERT_THAT(invocation->reader, IsEmpty());
              });
        }
        // Check back to make sure sum of the number for this thread is
        // correct.
        communicator->Invoke(
            kSumSelector,
            [](Communicator::Invocation *invocation) {
              // No input.
            },
            [this, thread_index](
                std::unique_ptr<Communicator::Invocation> invocation) {
              ASSERT_THAT(invocation->reader, SizeIs(1));
              const int64_t sum_for_thread = invocation->reader.next<int64_t>();
              const int64_t expected_sum_for_thread =
                  thread_index * kTotalMessages * kTotalMessages +
                  (kTotalMessages - 1) * kTotalMessages / 2;
              EXPECT_THAT(sum_for_thread, Eq(expected_sum_for_thread))
                  << thread_index;
            });
      });
    }
    // Wait for all threads to join.
    for (auto &thread : threads) {
      thread.Join();
    }
    threads.clear();
  }

  ABSL_CONST_INIT static thread_local int64_t thread_sum_;
};

ABSL_CONST_INIT thread_local int64_t
    MultithreadedWithThreadLocalStorageTest::thread_sum_ = 0;

class DuplexNestedMultithreadedInvokesTest : public CommunicatorTestFixture {
 public:
  DuplexNestedMultithreadedInvokesTest() = default;

 private:
  const uint64_t kSelector = 1234;

  void SetHandler(ServerHandlerMock *handler,
                  Communicator *communicator) override {
    // Handler that performs one level of Fibonacci numbers recursion.
    // Used by both target and host side of the communicator.
    // Target and host sides handlers are identical: they perform
    // nested asynchronous calls unless the input is 0 or 1.
    // Note that this handler never blocks.
    EXPECT_CALL(*handler, Call(NotNull()))
        .WillRepeatedly(
            [this, communicator](
                std::unique_ptr<Communicator::Invocation> invocation) {
              const auto current_thread_id = Thread::this_thread_id();
              ASYLO_ASSERT_OK(invocation->status);
              ASSERT_THAT(invocation->selector, Eq(kSelector));
              // Consume input.
              ASSERT_THAT(invocation->reader, SizeIs(1));
              const uint64_t input = invocation->reader.next<uint64_t>();
              if (communicator->is_host()) {
                ASSERT_THAT(invocation->invocation_thread_id,
                            Eq(current_thread_id));
              }
              // Produce output.
              if (input <= 1) {
                invocation->writer.Push(input);
                return;
              }

              // Make two nested calls concurrently for (input - 1) and (input
              // - 2), passing current 'invocation' converted into shared
              // pointer. When responded, each one will update write sum to
              // invocation->writer and then drop the shared pointer. Once both
              // added references are dropped, the current 'invocation' will
              // return the response. Note: all nested calls' callbacks are
              // handled on one thread, so there is no need to mutex-guard the
              // result. Their respective order is undefined, which is fine in
              // this case; if a specific order was needed, one would have to
              // daisy-chain the nested calls instead.
              uint64_t output = 0;
              std::shared_ptr<Communicator::Invocation> invocation_enclosure =
                  std::move(invocation);
              // From now on 'invocation' can no longer be used, only
              // 'invocation_enclosure' can.
              for (const uint64_t sub_input : {input - 1, input - 2}) {
                communicator->Invoke(
                    invocation_enclosure->selector,
                    [sub_input](Communicator::Invocation *nested_invocation) {
                      nested_invocation->writer.Push(sub_input);
                    },
                    [communicator, &output, current_thread_id](
                        std::unique_ptr<Communicator::Invocation>
                            nested_invocation) {
                      ASYLO_ASSERT_OK(nested_invocation->status);
                      if (communicator->is_host()) {
                        ASSERT_THAT(nested_invocation->invocation_thread_id,
                                    Eq(current_thread_id));
                      }
                      ASSERT_THAT(nested_invocation->reader, SizeIs(1));
                      output += nested_invocation->reader.next<uint64_t>();
                    });
              }
              invocation_enclosure->writer.Push(output);
            });
  }

  void RunAction(Communicator *communicator) override {
    // Host side makes the outermost calls on separate threads and verifies
    // results.
    const uint64_t fibo_results[] = {0,   1,   1,   2,    3,    5,   8,
                                     13,  21,  34,  55,   89,   144, 233,
                                     377, 610, 987, 1597, 2584, 4181};
    std::vector<Thread> threads;
    for (int t = 0; t < ABSL_ARRAYSIZE(fibo_results); ++t) {
      const uint64_t expected_result = fibo_results[t];
      threads.emplace_back([this, communicator, t, expected_result] {
        const auto current_thread_id = Thread::this_thread_id();
        communicator->Invoke(
            kSelector,
            [t](Communicator::Invocation *invocation) {
              // Fill in the outermost invocation parameters with the
              // nesting level (handling this message will make nested
              // call to the counterpart router with nesting level
              // decremented by one, until it reaches zero and returns
              // without more nesting) and current thread id as an
              // originator.
              invocation->writer.Push<uint64_t>(t);
            },
            [expected_result, current_thread_id](
                std::unique_ptr<Communicator::Invocation> invocation) {
              ASYLO_ASSERT_OK(invocation->status);
              ASSERT_THAT(invocation->invocation_thread_id,
                          Eq(current_thread_id));
              ASSERT_THAT(invocation->reader, SizeIs(1));
              EXPECT_THAT(invocation->reader.next<uint64_t>(),
                          Eq(expected_result));
            });
      });
    }

    // Wait for all threads to join.
    for (auto &thread : threads) {
      thread.Join();
    }
    threads.clear();
  }
};

class UnknownSelectorTest : public CommunicatorTestFixture {
 public:
  UnknownSelectorTest() = default;

 private:
  const uint64_t kBadSelector = 1234;

  void SetTargetHandler(ServerHandlerMock *handler,
                        Communicator *communicator) override {
    EXPECT_CALL(*handler, Call(NotNull()))
        .WillOnce([this](std::unique_ptr<Communicator::Invocation> invocation) {
          ASSERT_THAT(invocation->selector, Eq(kBadSelector));
          invocation->status =
              Status(absl::StatusCode::kNotFound, "Bad selector");
        });
  }

  void RunAction(Communicator *communicator) override {
    const auto current_thread_id = Thread::this_thread_id();
    communicator->Invoke(
        kBadSelector,
        [](Communicator::Invocation *invocation) {
          // No input.
        },
        [current_thread_id](
            std::unique_ptr<Communicator::Invocation> invocation) {
          EXPECT_THAT(invocation->status,
                      StatusIs(absl::StatusCode::kNotFound));
          ASSERT_THAT(invocation->invocation_thread_id, Eq(current_thread_id));
          ASSERT_THAT(invocation->reader, IsEmpty());
        });
  }
};

class OpenCensusClientTest : public CommunicatorTestFixture {
 public:
  OpenCensusClientTest() = default;

 private:
  // A MockExporter for OpenCensus metrics. This exporter is an Observer
  // registered with the OpenCensus StatsExporter singleton which utilizes the
  // Observer pattern to regularly notify Observers.
  class MockExporter : public ::opencensus::stats::StatsExporter::Handler {
   public:
    static void Register(
        MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>>
            *output) {
      opencensus::stats::StatsExporter::RegisterPushHandler(
          absl::make_unique<MockExporter>(output));
    }

    explicit MockExporter(
        MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> *output)
        : output_(output) {}

    void ExportViewData(
        const std::vector<std::pair<ViewDescriptor, ViewData>> &data) override {
      for (const auto &datum : data) {
        output_->Lock()->emplace_back(datum.first, datum.second);
      }
    }

   private:
    MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> *output_;
  };

  // Tests that metrics are actually collected. The validity of the collected
  // metrics are measured in the unit tests of OpenCensusClient. There are 14
  // different data points collected by OpenCensusClient, so we wait until at
  // least one measure of each datapoint is collected.
  void RunAction(Communicator *communicator) override {
    MutexGuarded<std::vector<std::pair<ViewDescriptor, ViewData>>> output_(
        std::vector<std::pair<ViewDescriptor, ViewData>>({}));
    MockExporter::Register(&output_);

    // Wait until one measure of each metric is collected. These metrics are
    // collected regularly based on the granularity we've set in the
    // OpenCensusClientConfig- but sent intermittently by the StatsExporter. So
    // we have to just wait for them to arrive.
    while (output_.ReaderLock()->size() < 14) {
      absl::SleepFor(absl::Seconds(1));
    }
    ASSERT_THAT(output_.ReaderLock()->size(), Eq(14));
  }
};

void RegisterAllTests() {
  // Prepare all the tests (before forking the process - so that both host and
  // target processes see them), do not store pointers - they are handed over
  // to the test registry to own.
  CommunicatorTestFixture::Register<NoInvokesTest>();
  CommunicatorTestFixture::Register<SingleInvokeTest>();
  CommunicatorTestFixture::Register<InvokeAndCountTest>();
  CommunicatorTestFixture::Register<MultithreadedInvokesAndCheckBackTest>();
  CommunicatorTestFixture::Register<MultithreadedWithThreadLocalStorageTest>();
  CommunicatorTestFixture::Register<DuplexNestedMultithreadedInvokesTest>();
  CommunicatorTestFixture::Register<UnknownSelectorTest>();
  CommunicatorTestFixture::Register<OpenCensusClientTest>();
}

}  // namespace test
}  // namespace primitives
}  // namespace asylo

int main(int argc, char *argv[]) {
  // Prepare all the tests before forking the process - so that both host and
  // target processes see them.
  ::asylo::primitives::test::RegisterAllTests();

  // Fork the process (joined by TearDownTestCase after all the tests finished).
  ::asylo::primitives::test::CommunicatorTestFixture::ForkProcess();

  ::testing::InitGoogleTest(&argc, argv);
  ::absl::ParseCommandLine(argc, argv);

  // Run the tests on both host and target; TearDownTestCase of the parent
  // process waits for the child process to shut down.
  return RUN_ALL_TESTS();
}
