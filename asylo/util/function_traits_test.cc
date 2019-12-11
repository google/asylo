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

#include "asylo/util/function_traits.h"

#include <cstdint>
#include <functional>
#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

// It is necessary that we test the following types of anonymous functions:
// * std::functions
// * lambdas
// * callable objects (objects implementing operator())
// * function pointers
// * member function pointers

// A parameterized function, which we can use to get a function
// pointer of various types.
template <typename Ret, typename... Args>
Ret Fun(Args... args) {
  return Ret();
}

// A parameterized class which can act as a callable itself, has a member
// function which can be pointed at, and has a static member as well.
template <typename Ret, typename... Args>
class FunClass {
 public:
  Ret operator()(Args... args) { return Ret(); }
  Ret MemberFun(Args... args) { return Ret(); }
  Ret ConstMemberFun(Args... args) const { return Ret(); }
  static Ret StaticFun(Args... args) { return Ret(); }
};

// Make some distinct classes, which allow us to have some distinct concrete
// types to play with.
class A {};
class B {};
class C {};
class D {};

// 'TypecheckFunctionArguments' allows for compile time type
// checking of argument types to anonymous functions. For example, we
// could guarantee that an anonymous function f took exactly 1 int
// argument by writing:
// TypecheckFunctionArguments<int>(f);
// in our code.
template <typename... Expected, typename FuncT>
void TypecheckFunctionArguments(FuncT f) {
  static_assert(
      FunctionTraits<FuncT>::template CheckArgumentTypes<Expected...>::value,
      "Expected argument types dont match");
}

// 'typecheck_function_argument' allows for compile time type checking
// of the return type of anonymous functions. For example, we could
// guarantee that an anonymous function f returns a bool by writing:
// TypecheckFunctionReturn<bool>(f);
// in our code.
template <typename Expected, typename FuncT>
void TypecheckFunctionReturn(FuncT f) {
  static_assert(
      FunctionTraits<FuncT>::template CheckReturnType<Expected>::value,
      "Expected return type doesn't match");
}

TEST(FunctionTraitsNegativeTest, DifferentNumberArguments) {
  auto fn0 = []() { return 0; };
  static_assert(
      !FunctionTraits<decltype(fn0)>::template CheckArgumentTypes<int>::value,
      "somehow 0 == 1");
  auto fn2 = [](int x, int y) { return 'c'; };
  static_assert(
      !FunctionTraits<decltype(fn2)>::template CheckArgumentTypes<int>::value,
      "somehow 2 == 1");
}

TEST(FunctionTraitsNegativeTest, DifferentTypeArguments) {
  auto fn_int_int = [](int x, int y) { return 'c'; };
  static_assert(
      !FunctionTraits<decltype(
          fn_int_int)>::template CheckArgumentTypes<char *, int>::value,
      "somehow char * is int");
  auto fn_char_int_ptr = [](char x, int *y) { return 'c'; };
  static_assert(
      !FunctionTraits<decltype(
          fn_char_int_ptr)>::template CheckArgumentTypes<char *, bool>::value,
      "somehow char is char * or bool is int *");
  auto fn_char = [](char x) { return 'c'; };
  static_assert(!FunctionTraits<decltype(
                    fn_char)>::template CheckArgumentTypes<int>::value,
                "somehow char is int");
  auto fn_int = [](int y) { return 'c'; };
  static_assert(!FunctionTraits<decltype(
                    fn_int)>::template CheckArgumentTypes<char>::value,
                "somehow int is char");
}

TEST(FunctionTraitsNegativeTest, DifferentTypeResult) {
  auto fn_int = []() { return 5; };
  static_assert(
      !FunctionTraits<decltype(fn_int)>::template CheckReturnType<bool>::value,
      "somehow bool is int");
  auto fn_bool = []() { return true; };
  static_assert(
      !FunctionTraits<decltype(fn_bool)>::template CheckReturnType<int>::value,
      "somehow int is bool");
}

TEST(FunctionTraitsWeirdTypesTest, ReferenceTest) {
  auto fn_A_ref = [](const A &a) { return 5; };
  TypecheckFunctionArguments<const A &>(fn_A_ref);
  TypecheckFunctionReturn<int>(fn_A_ref);
}

TEST(FunctionTraitsWeirdTypesTest, ReturnVoidTest) {
  auto fn_int = [](int x) {};
  TypecheckFunctionArguments<int>(fn_int);
  TypecheckFunctionReturn<void>(fn_int);
  static_assert(
      FunctionTraits<decltype(
          &FunClass<void>::MemberFun)>::template CheckReturnType<void>::value,
      "expected void return type");
  static_assert(FunctionTraits<decltype(&FunClass<void>::ConstMemberFun)>::
                    template CheckReturnType<void>::value,
                "expected void return type");
  static_assert(
      FunctionTraits<decltype(
          &FunClass<void>::StaticFun)>::template CheckReturnType<void>::value,
      "expected void return type");
}

class NoCopyOrMove {
 public:
  NoCopyOrMove(const NoCopyOrMove &) = delete;
  const NoCopyOrMove &operator=(const NoCopyOrMove &) = delete;
};

TEST(FunctionTraitsWeirdTypesTest, CopylessTest) {
  auto fn_no_copy = [](const NoCopyOrMove &x) { return 5; };
  TypecheckFunctionArguments<const NoCopyOrMove &>(fn_no_copy);
  TypecheckFunctionReturn<int>(fn_no_copy);
}

class NoPublicDestructor {
 public:
  NoPublicDestructor(const NoPublicDestructor &) = delete;
  const NoPublicDestructor &operator=(const NoPublicDestructor &) = delete;

 private:
  ~NoPublicDestructor() = default;
};

TEST(FunctionTraitsWeirdTypesTest, DestructlessTest) {
  auto fn_no_destruct = [](const NoPublicDestructor &x) { return 5; };
  TypecheckFunctionArguments<const NoPublicDestructor &>(fn_no_destruct);
  TypecheckFunctionReturn<int>(fn_no_destruct);
}

template <class T>
class FunctionTraitsTestReturn : public testing::Test {};

TYPED_TEST_SUITE_P(FunctionTraitsTestReturn);

TYPED_TEST_P(FunctionTraitsTestReturn, LambdaReturnType) {
  auto fn0 = []() { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn0);
  auto fn1 = [](int x) { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn1);
  auto fn11 = [](TypeParam *x) { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn11);
  auto fn2 = [](char x, double y) { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn2);
  auto fn5 = [](char x, double y, int z, float w, int64_t v) {
    return TypeParam();
  };
  TypecheckFunctionReturn<TypeParam>(fn5);
}

TYPED_TEST_P(FunctionTraitsTestReturn, StdFunctionReturnType) {
  std::function<TypeParam()> fn0 = []() { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn0);
  std::function<TypeParam(int)> fn1 = [](int x) { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn1);
  std::function<TypeParam(TypeParam *)> fn11 = [](TypeParam *x) {
    return TypeParam();
  };
  TypecheckFunctionReturn<TypeParam>(fn11);
  std::function<TypeParam(char, double)> fn2 = [](char x, double y) {
    return TypeParam();
  };
  TypecheckFunctionReturn<TypeParam>(fn2);
  std::function<TypeParam(char, double, int, float, int64_t)> fn5 =
      [](char x, double y, int z, float w, int64_t v) { return TypeParam(); };
  TypecheckFunctionReturn<TypeParam>(fn5);
};

TYPED_TEST_P(FunctionTraitsTestReturn, CallableReturnType) {
  FunClass<TypeParam> fn0;
  TypecheckFunctionReturn<TypeParam>(fn0);
  FunClass<TypeParam, int> fn1;
  TypecheckFunctionReturn<TypeParam>(fn1);
  FunClass<TypeParam, TypeParam *> fn11;
  TypecheckFunctionReturn<TypeParam>(fn11);
  FunClass<TypeParam, char, double> fn2;
  TypecheckFunctionReturn<TypeParam>(fn2);
  FunClass<TypeParam, char, double, int, float, int64_t> fn5;
  TypecheckFunctionReturn<TypeParam>(fn5);
}

TYPED_TEST_P(FunctionTraitsTestReturn, FunctionPointerReturnType) {
  TypeParam (*fn0)() = Fun<TypeParam>;
  TypecheckFunctionReturn<TypeParam>(fn0);
  TypeParam (*fn1)(int) = Fun<TypeParam, int>;
  TypecheckFunctionReturn<TypeParam>(fn1);
  TypeParam (*fn11)(TypeParam *) = Fun<TypeParam, TypeParam *>;
  TypecheckFunctionReturn<TypeParam>(fn11);
  TypeParam (*fn2)(char, double) = Fun<TypeParam, char, double>;
  TypecheckFunctionReturn<TypeParam>(fn2);
  TypeParam (*fn5)(char, double, int, float, int64_t) =
      Fun<TypeParam, char, double, int, float, int64_t>;
  TypecheckFunctionReturn<TypeParam>(fn5);
}

TYPED_TEST_P(FunctionTraitsTestReturn, ConstFunctionPointerReturnType) {
  TypeParam (*const fn0)() = Fun<TypeParam>;
  TypecheckFunctionReturn<TypeParam>(fn0);
  TypeParam (*const fn1)(int) = Fun<TypeParam, int>;
  TypecheckFunctionReturn<TypeParam>(fn1);
  TypeParam (*const fn11)(TypeParam *) = Fun<TypeParam, TypeParam *>;
  TypecheckFunctionReturn<TypeParam>(fn11);
  TypeParam (*const fn2)(char, double) = Fun<TypeParam, char, double>;
  TypecheckFunctionReturn<TypeParam>(fn2);
  TypeParam (*const fn5)(char, double, int, float, int64_t) =
      Fun<TypeParam, char, double, int, float, int64_t>;
  TypecheckFunctionReturn<TypeParam>(fn5);
}

TYPED_TEST_P(FunctionTraitsTestReturn, StaticMemberFunctionPointerReturnType) {
  TypecheckFunctionReturn<TypeParam>(&FunClass<TypeParam>::StaticFun);
  TypecheckFunctionReturn<TypeParam>(&FunClass<TypeParam, int>::StaticFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, TypeParam *>::StaticFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, char, double>::StaticFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, char, double, int, float, int64_t>::StaticFun);
}

TYPED_TEST_P(FunctionTraitsTestReturn, MemberFunctionPointerReturnType) {
  TypecheckFunctionReturn<TypeParam>(&FunClass<TypeParam>::MemberFun);
  TypecheckFunctionReturn<TypeParam>(&FunClass<TypeParam, int>::MemberFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, TypeParam *>::MemberFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, char, double>::MemberFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, char, double, int, float, int64_t>::MemberFun);
}

TYPED_TEST_P(FunctionTraitsTestReturn, ConstMemberFunctionPointerReturnType) {
  TypecheckFunctionReturn<TypeParam>(&FunClass<TypeParam>::ConstMemberFun);
  TypecheckFunctionReturn<TypeParam>(&FunClass<TypeParam, int>::ConstMemberFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, TypeParam *>::ConstMemberFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, char, double>::ConstMemberFun);
  TypecheckFunctionReturn<TypeParam>(
      &FunClass<TypeParam, char, double, int, float, int64_t>::ConstMemberFun);
}

REGISTER_TYPED_TEST_SUITE_P(FunctionTraitsTestReturn, LambdaReturnType,
                            StdFunctionReturnType, CallableReturnType,
                            FunctionPointerReturnType,
                            ConstFunctionPointerReturnType,
                            StaticMemberFunctionPointerReturnType,
                            MemberFunctionPointerReturnType,
                            ConstMemberFunctionPointerReturnType);

template <class T>
class FunctionTraitsTestArguments : public testing::Test {};

TYPED_TEST_SUITE_P(FunctionTraitsTestArguments);

TYPED_TEST_P(FunctionTraitsTestArguments, LambdaArgumentTypes) {
  auto fn0 = []() { return TypeParam(); };
  TypecheckFunctionArguments<>(fn0);
  auto fn1 = [](int x) { return TypeParam(); };
  TypecheckFunctionArguments<int>(fn1);
  auto fn11 = [](TypeParam x) { return x; };
  TypecheckFunctionArguments<TypeParam>(fn11);
  auto fn4 = [](A *x, double y, const B *z, TypeParam w) {
    return TypeParam();
  };
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(fn4);
  auto fn6 = [](TypeParam a, char x, double y, const C &z, A *w,
                volatile B *v) { return TypeParam(); };
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(fn6);
}

TYPED_TEST_P(FunctionTraitsTestArguments, StdFunctionArgumentTypes) {
  std::function<TypeParam()> fn0 = []() { return TypeParam(); };
  TypecheckFunctionArguments<>(fn0);
  std::function<TypeParam(int)> fn1 = [](int x) { return TypeParam(); };
  TypecheckFunctionArguments<int>(fn1);
  std::function<TypeParam(TypeParam)> fn11 = [](TypeParam x) { return x; };
  TypecheckFunctionArguments<TypeParam>(fn11);
  std::function<TypeParam(A *, double, const B *, TypeParam)> fn4 =
      [](A *x, double y, const B *z, TypeParam w) { return TypeParam(); };
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(fn4);
  std::function<TypeParam(TypeParam, char, double, const C &, A *,
                          volatile B *)>
      fn6 = [](TypeParam a, char x, double y, const C &z, A *w, volatile B *v) {
        return TypeParam();
      };
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(fn6);
}

TYPED_TEST_P(FunctionTraitsTestArguments, CallableArgumentTypes) {
  FunClass<TypeParam> fn0;
  TypecheckFunctionArguments<>(fn0);
  FunClass<TypeParam, int> fn1;
  TypecheckFunctionArguments<int>(fn1);
  FunClass<TypeParam, TypeParam> fn11;
  TypecheckFunctionArguments<TypeParam>(fn11);
  FunClass<TypeParam, A *, double, const B *, TypeParam> fn4;
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(fn4);
  FunClass<TypeParam, TypeParam, char, double, const C &, A *, volatile B *>
      fn6;
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(fn6);
}

TYPED_TEST_P(FunctionTraitsTestArguments, FunctionPointerArgumentTypes) {
  TypeParam (*fn0)() = Fun<TypeParam>;
  TypecheckFunctionArguments<>(fn0);
  TypeParam (*fn1)(int) = Fun<TypeParam, int>;
  TypecheckFunctionArguments<int>(fn1);
  TypeParam (*fn11)(TypeParam) = Fun<TypeParam, TypeParam>;
  TypecheckFunctionArguments<TypeParam>(fn11);
  TypeParam (*fn4)(A *, double, const B *, TypeParam) =
      Fun<TypeParam, A *, double, const B *, TypeParam>;
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(fn4);
  TypeParam (*fn6)(TypeParam, char, double, const C &, A *, volatile B *) =
      Fun<TypeParam, TypeParam, char, double, const C &, A *, volatile B *>;
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(fn6);
}

TYPED_TEST_P(FunctionTraitsTestArguments, ConstFunctionPointerArgumentTypes) {
  TypeParam (*const fn0)() = Fun<TypeParam>;
  TypecheckFunctionArguments<>(fn0);
  TypeParam (*const fn1)(int) = Fun<TypeParam, int>;
  TypecheckFunctionArguments<int>(fn1);
  TypeParam (*const fn11)(TypeParam) = Fun<TypeParam, TypeParam>;
  TypecheckFunctionArguments<TypeParam>(fn11);
  TypeParam (*const fn4)(A *, double, const B *, TypeParam) =
      Fun<TypeParam, A *, double, const B *, TypeParam>;
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(fn4);
  TypeParam (*const fn6)(TypeParam, char, double, const C &, A *,
                         volatile B *) =
      Fun<TypeParam, TypeParam, char, double, const C &, A *, volatile B *>;
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(fn6);
}

TYPED_TEST_P(FunctionTraitsTestArguments,
             StaticMemberFunctionPointerArgumentTypes) {
  TypecheckFunctionArguments<>(&FunClass<TypeParam>::StaticFun);
  TypecheckFunctionArguments<int>(&FunClass<TypeParam, int>::StaticFun);
  TypecheckFunctionArguments<TypeParam>(
      &FunClass<TypeParam, TypeParam>::StaticFun);
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(
      &FunClass<TypeParam, A *, double, const B *, TypeParam>::StaticFun);
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(
      &FunClass<TypeParam, TypeParam, char, double, const C &, A *,
                volatile B *>::StaticFun);
}

TYPED_TEST_P(FunctionTraitsTestArguments, MemberFunctionPointerArgumentTypes) {
  TypecheckFunctionArguments<>(&FunClass<TypeParam>::MemberFun);
  TypecheckFunctionArguments<int>(&FunClass<TypeParam, int>::MemberFun);
  TypecheckFunctionArguments<TypeParam>(
      &FunClass<TypeParam, TypeParam>::MemberFun);
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(
      &FunClass<TypeParam, A *, double, const B *, TypeParam>::MemberFun);
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(
      &FunClass<TypeParam, TypeParam, char, double, const C &, A *,
                volatile B *>::MemberFun);
}

TYPED_TEST_P(FunctionTraitsTestArguments,
             ConstMemberFunctionPointerArgumentTypes) {
  TypecheckFunctionArguments<>(&FunClass<TypeParam>::ConstMemberFun);
  TypecheckFunctionArguments<int>(&FunClass<TypeParam, int>::ConstMemberFun);
  TypecheckFunctionArguments<TypeParam>(
      &FunClass<TypeParam, TypeParam>::ConstMemberFun);
  TypecheckFunctionArguments<A *, double, const B *, TypeParam>(
      &FunClass<TypeParam, A *, double, const B *, TypeParam>::ConstMemberFun);
  TypecheckFunctionArguments<TypeParam, char, double, const C &, A *,
                             volatile B *>(
      &FunClass<TypeParam, TypeParam, char, double, const C &, A *,
                volatile B *>::ConstMemberFun);
}

REGISTER_TYPED_TEST_SUITE_P(FunctionTraitsTestArguments, LambdaArgumentTypes,
                            StdFunctionArgumentTypes, CallableArgumentTypes,
                            FunctionPointerArgumentTypes,
                            ConstFunctionPointerArgumentTypes,
                            StaticMemberFunctionPointerArgumentTypes,
                            MemberFunctionPointerArgumentTypes,
                            ConstMemberFunctionPointerArgumentTypes);

typedef testing::Types<A, B, C, D> TypeList;
typedef testing::Types<int, char, bool, int16_t, int64_t, double, float>
    BaseTypeList;
typedef testing::Types<A *, B *, C *, D *> PointerTypeList;
typedef testing::Types<const A *, const B *, const C *, const D *>
    ConstPointerTypeList;
typedef testing::Types<void> VoidTypeList;

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsReturn, FunctionTraitsTestReturn,
                               TypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsBaseReturn,
                               FunctionTraitsTestReturn, BaseTypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsPointerReturn,
                               FunctionTraitsTestReturn, PointerTypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsVoidReturn,
                               FunctionTraitsTestReturn, VoidTypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsArguments,
                               FunctionTraitsTestArguments, TypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsBaseArguments,
                               FunctionTraitsTestArguments, BaseTypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsPointerArguments,
                               FunctionTraitsTestArguments, PointerTypeList);

INSTANTIATE_TYPED_TEST_SUITE_P(FunctionTraitsConstPointerArguments,
                               FunctionTraitsTestArguments,
                               ConstPointerTypeList);

}  // namespace
}  // namespace asylo
