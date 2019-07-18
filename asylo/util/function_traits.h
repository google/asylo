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

#ifndef ASYLO_UTIL_FUNCTION_TRAITS_H_
#define ASYLO_UTIL_FUNCTION_TRAITS_H_

#include <tuple>

// This library abstracts the specific kind of an anonymous function away
// from the programmer, and allows them to statically assert that any
// anonymous function has the argument types and return type they
// expect.
//
// This is necessary due to the myriad of different kinds of anonymous
// functions in C++. This example:
// static_assert(std::is_convertible<
//                 FunctionTypeInQuestion,
//                 std::function<ReturnType(ArgTypes)>>::value);
// will permit more type conversions than might be desired
// (e.g. std::function<char(char)> is convertible into
// std::function<bool(int)>). However, replacing std::is_convertible with
// std::is_same will disallow FunctionTypeInQuestion from being any other
// kind of anonymous function (including lambdas).
//
// This library allows for easy use of the preferred way to pass anonymous
// functions (i.e. passing the type of the anonymous function as a template
// parameter), which can be slightly more efficient than passing std::functions.
// For example:
//
// template <typename FuncT>
// int CallTwiceAndSum(FuncT f) {
//   // Statically assert that f returns an int
//   static_assert(std::is_same<int,
//                 typename FunctionTraits<FuncT>::ReturnType>::value,
//                 "Expected return type of int");
//   // Statically assert that f takes no arguments
//   static_assert(std::is_same<std::tuple<>,
//                 typename FunctionTraits<FuncT>::ArgumentTypes>::value,
//                 "Expected no arguments");
//   return f() + f();
// }
//
// Function Traits allows extraction of the exact argument types and
// return type of anonymous functions, whether they are:
// * std::functions
// * lambdas
// * callable objects (objects implementing operator())
// * function pointers
// * member function pointers
template <typename FuncT>
struct FunctionTraits {
 private:
  // Grab the argument types of a function pointer or static member
  // function pointer. Package up into a tuple to support any number of
  // arguments.
  template <typename RetT, typename... ArgsT>
  static std::tuple<ArgsT...> ArgumentTypesHelper(RetT (*)(ArgsT...));

  // Grab the argument types of a callable object or a member function
  // pointer. Package up into a tuple type to support any number of
  // arguments.
  template <typename RetT, typename F, typename... ArgsT>
  static std::tuple<ArgsT...> ArgumentTypesHelper(RetT (F::*)(ArgsT...));

  // Grab the argument types of a lambda or a std::function. Package up
  // into a tuple type to support any number of arguments.
  template <typename RetT, typename F, typename... ArgsT>
  static std::tuple<ArgsT...> ArgumentTypesHelper(RetT (F::*)(ArgsT...) const);

  // Grab the result type of a function pointer or static function pointer.
  template <typename RetT, typename... ArgsT>
  static RetT ReturnTypeHelper(RetT (*)(ArgsT...));

  // Grab the result type of a callable object or member function pointer.
  template <typename RetT, typename F, typename... ArgsT>
  static RetT ReturnTypeHelper(RetT (F::*)(ArgsT...));

  // Grab the result type of a lambda or a std::function.
  template <typename RetT, typename F, typename... ArgsT>
  static RetT ReturnTypeHelper(RetT (F::*)(ArgsT...) const);

  // Allow 'ArgumentTypesHelper' to resolve to the appropriate
  // definition depending on the function type FuncT.
  template <typename F>
  static auto ArgumentTypesHelper(F)
      -> decltype(ArgumentTypesHelper(&F::operator()));

  // Allow 'ReturnTypeHelper' to resolve to the appropriate
  // definition depending on the function type FuncT.
  template <typename F>
  static auto ReturnTypeHelper(F) -> decltype(ReturnTypeHelper(&F::operator()));

 public:
  // 'ArgumentTypes' yields a std::tuple type which corresponds to
  // FuncT's argument types. For example,
  // FunctionTraits<std::function<int(char,bool)>>::ArgumentTypes
  // would be std::tuple<char,bool>.
  using ArgumentTypes = decltype(ArgumentTypesHelper(std::declval<FuncT>()));

  // 'ReturnType' yields a type which corresponds to FuncT's return
  // type. For example,
  // FunctionTraits<std::function<int(char,bool)>>::ReturnType would
  // be int.
  using ReturnType = decltype(ReturnTypeHelper(std::declval<FuncT>()));

  // 'CheckArgumentTypes' takes any number of types, and yields a
  // bool. That bool is true only if those types given match FuncT's
  // argument types exactly. For example,
  // FunctionTraits<std::function<int(char,bool)>>::template
  //                CheckArgumentTypes<char,bool>::value
  // would be true.
  template <typename... Expected>
  struct CheckArgumentTypes {
    static constexpr bool value =
        std::is_same<ArgumentTypes, std::tuple<Expected...>>::value;
  };

  // 'CheckReturnType' takes a type, and yields a bool. That bool is
  // true only if the given type matches FuncT's return type
  // exactly. For example,
  // FunctionTraits<std::function<int(char,bool)>>::template
  //                CheckReturnType<int>::value
  // would be true.
  template <typename Expected>
  struct CheckReturnType {
    static constexpr bool value = std::is_same<ReturnType, Expected>::value;
  };
};

#endif  // ASYLO_UTIL_FUNCTION_TRAITS_H_
