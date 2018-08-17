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

#include <math.h>

extern "C" {

long double acoshl(long double x) { return __builtin_acoshl(x); }
long double asinhl(long double x) { return __builtin_asinhl(x); }
long double atanhl(long double x) { return __builtin_atanhl(x); }
long double cbrtl(long double x) { return __builtin_cbrtl(x); }
long double copysignl(long double x, long double y) {
  return __builtin_copysignl(x, y);
}
long double erfl(long double x) { return __builtin_erfl(x); }
long double erfcl(long double x) { return __builtin_erfcl(x); }
long double exp2l(long double x) { return __builtin_exp2l(x); }
long double expm1l(long double x) { return __builtin_expm1l(x); }
long double fdiml(long double x, long double y) {
  return __builtin_fdiml(x, y);
}
long double fmal(long double x, long double y, long double z) {
  return __builtin_fmal(x, y, z);
}
long double fmaxl(long double x, long double y) {
  return __builtin_fmaxl(x, y);
}
long double fminl(long double x, long double y) {
  return __builtin_fminl(x, y);
}
int ilogbl(long double x) { return __builtin_ilogbl(x); }
long double lgammal(long double x) { return __builtin_lgammal(x); }
long long int llrintl(long double x) {
  return __builtin_llrintl(x);
}
long long int llroundl(long double x) {
  return __builtin_llroundl(x);
}
long double log1pl(long double x) { return __builtin_log1pl(x); }
long double log2l(long double x) { return __builtin_log2l(x); }
long double logbl(long double x) { return __builtin_logbl(x); }
long int lrintl(long double x) {
  return __builtin_lrintl(x);
}
long int lroundl(long double x) {
  return __builtin_lroundl(x);
}
long double nanl(const char *x) { return __builtin_nanl(x); }
long double nearbyintl(long double x) { return __builtin_nearbyintl(x); }
long double nextafterl(long double x, long double y) {
  return __builtin_nextafterl(x, y);
}
double nexttoward(double x, long double y) {
  return __builtin_nexttoward(x, y);
}
float nexttowardf(float x, long double y) {
  return __builtin_nexttowardf(x, y);
}
long double nexttowardl(long double x, long double y) {
  return __builtin_nexttowardl(x, y);
}
long double remainderl(long double x, long double y) {
  return __builtin_remainderl(x, y);
}
long double remquol(long double x, long double y, int *z) {
  return __builtin_remquol(x, y, z);
}
long double rintl(long double x) { return __builtin_rintl(x); }
long double roundl(long double x) { return __builtin_roundl(x); }
long double scalblnl(long double x, long int y) {
  return __builtin_scalblnl(x, y);
}
long double scalbnl(long double x, int y) { return __builtin_scalbnl(x, y); }
long double tgammal(long double x) { return __builtin_tgammal(x); }
long double truncl(long double x) { return __builtin_truncl(x); }

}  // extern "C"
