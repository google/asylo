/*
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
 */

#include <openssl/bn.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <iostream>
#include <vector>

#include "asylo/crypto/util/bssl_util.h"

// Parse an RSA private key in DER format and return a pointer to an object that
// represents the RSA key in memory. In other parts of this interface we refer to
// this object as `rsa_key`
extern "C" void* fortanix_edp_crypto_parse_rsa_private_key_der(const uint8_t * der, size_t der_len) {
  RSA* private_key = RSA_private_key_from_bytes(der, der_len);
  if (!private_key) {
    std::cout << "fortanix_edp_crypto_parse_rsa_private_key_der: " << asylo::BsslLastErrorString() << "\n";
    return nullptr;
  }
  return private_key;
}

// Free the RSA key object
extern "C" void fortanix_edp_crypto_free_rsa_key(void* rsa_key) {
  RSA* private_key = (RSA*) rsa_key;
  RSA_free(private_key);
}

// Return the number of bits in the RSA key
extern "C" size_t fortanix_edp_crypto_rsa_key_len(void* rsa_key) {
  RSA* private_key = (RSA*) rsa_key;
  return RSA_bits(private_key);
}

// Retrieve the public modulus of RSA key in little-endian format.
// output is a buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
// This function should return:
// - number of bytes written to output on success,
// - negative value on failure.
extern "C" int fortanix_edp_crypto_rsa_key_modulus(void* rsa_key, uint8_t* output) {
  RSA* private_key = (RSA*) rsa_key;
  const BIGNUM *n = nullptr;
  RSA_get0_key(private_key, &n, /*e*/nullptr, /*d*/nullptr);
  if (!n) {
    return -1;
  }
  int rsa_bytes = RSA_size(private_key);
  int bignum_size = BN_num_bytes(n);
  if (bignum_size > rsa_bytes) {
    return -1;
  }
  int written = BN_bn2bin(n, output);
  std::reverse(output, output + written);
  return written;
}

// Retrieve the public exponent of RSA key in little-endian format.
// output is a buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
// This function should return:
// - number of bytes written to output on success,
// - negative value on failure.
extern "C" int fortanix_edp_crypto_rsa_key_exponent(void* rsa_key, uint8_t* output) {
  RSA* private_key = (RSA*) rsa_key;
  const BIGNUM *e = nullptr;
  RSA_get0_key(private_key, /*n*/nullptr, &e, /*d*/nullptr);
  if (!e) {
    return -1;
  }
  int rsa_bytes = RSA_size(private_key);
  int bignum_size = BN_num_bytes(e);
  if (bignum_size > rsa_bytes) {
    return -1;
  }
  int written = BN_bn2bin(e, output);
  std::reverse(output, output + written);
  return written;
}

// Generate an RSASSA-PKCS1-v1_5 signature over a SHA256 hash.
// hash is a 32 bytes long buffer and contains a SHA256 hash value.
// output is a buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
// signature should be written to output buffer in little-endian format.
// This function should return:
// - number of bytes written to output on success,
// - negative value on failure.
extern "C" int fortanix_edp_crypto_sign_sha256_pkcs1v1_5(void* rsa_key, const uint8_t* hash, uint8_t* output) {
  RSA* private_key = (RSA*) rsa_key;
  unsigned int out_len = 0;
  int r = RSA_sign(NID_sha256, hash, 32, output, &out_len, private_key);
  if (r != 1) {
    return -1;
  }
  std::reverse(output, output + out_len);
  return out_len;
}

// Verify an RSASSA-PKCS1-v1_5 signature `sig` over a SHA256 hash.
// hash is a 32 bytes long buffer and contains a SHA256 hash value.
// sig is a little-endian buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
// This function should return:
// - 0 if the signature is verified,
// - non-zero on failure.
extern "C" int fortanix_edp_crypto_verify_sha256_pkcs1v1_5(void* rsa_key, const uint8_t* hash, const uint8_t* sig) {
  RSA* private_key = (RSA*) rsa_key;
  int sig_len = RSA_size(private_key);
  std::vector<uint8_t> sig_copy(sig, sig + sig_len);
  std::reverse(sig_copy.begin(), sig_copy.end());
  int r = RSA_verify(NID_sha256, hash, 32, sig_copy.data(), sig_len, private_key);
  if (r != 1) {
    return -1;
  }
  return 0;
}
