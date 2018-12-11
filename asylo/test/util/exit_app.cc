/*
 *
 * Copyright 2017 Asylo authors
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

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>

void usage(int argc, char *argv[]) {
  std::cerr << "Expected usage: " << argv[0]
            << " --TEST_NAME\n"
               "Where TEST_NAME can be one of\n"
               "  exit3\n"
               "  printA\n"
               "  printB5\n"
               "  segfault\n"
               "  sigill\n"
               "  stderrFoo\n"
               "  stdin\n"
               "\nGiven: ";
  for (int i = 0; i < argc; ++i) {
    std::cerr << argv[i] << std::endl;
  }
  abort();
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage(argc, argv);
  }

  if (strcmp(argv[1], "--exit3") == 0) {
    exit(3);
  } else if (strcmp(argv[1], "--printA") == 0) {
    std::cout << "A" << std::endl;
  } else if (strcmp(argv[1], "--printB5") == 0) {
    for (int i = 0; i < 5; ++i) {
      std::cout << "B" << std::endl;
    }
  } else if (strcmp(argv[1], "--segfault") == 0) {
    raise(SIGSEGV);
  } else if (strcmp(argv[1], "--sigill") == 0) {
    raise(SIGILL);
  } else if (strcmp(argv[1], "--stdin") == 0) {
    int number = 0;
    std::cin >> number;
    if (number == 13) {
      std::cout << "Lucky!" << std::endl;
    } else {
      std::cout << "Fail." << std::endl;
    }
  } else if (strcmp(argv[1], "--stderrFoo") == 0) {
    std::cerr << "Foo" << std::endl;
  } else {
    usage(argc, argv);
  }
  return 0;
}
