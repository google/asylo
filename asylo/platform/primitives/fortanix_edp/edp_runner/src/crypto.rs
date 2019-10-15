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

use failure::{Compat, Fail};
use num_bigint::{BigUint};
use sgxs::crypto::SgxRsaOps;
use std::os::raw::{c_int, c_uchar, c_uint, c_void};

extern "C" {
    /// Parse an RSA private key in DER format and return a pointer to an object that
    /// represents the RSA key in memory. In other parts of this interface we refer to
    /// this object as `rsa_key`
    fn fortanix_edp_crypto_parse_rsa_private_key_der(der: *const c_uchar, der_len: c_uint) -> *mut c_void;

    /// Free the RSA key object
    fn fortanix_edp_crypto_free_rsa_key(rsa_key: *mut c_void);

    /// Return the number of bits in the RSA key
    fn fortanix_edp_crypto_rsa_key_len(rsa_key: *mut c_void) -> c_uint;

    /// Retrieve the public modulus of RSA key in little-endian format.
    /// output is a buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
    /// This function should return:
    /// - number of bytes written to output on success,
    /// - negative value on failure.
    fn fortanix_edp_crypto_rsa_key_modulus(rsa_key: *mut c_void, output: *mut c_uchar) -> c_int;

    /// Retrieve the public exponent of RSA key in little-endian format.
    /// output is a buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
    /// This function should return:
    /// - number of bytes written to output on success,
    /// - negative value on failure.
    fn fortanix_edp_crypto_rsa_key_exponent(rsa_key: *mut c_void, output: *mut c_uchar) -> c_int;

    /// Generate an RSASSA-PKCS1-v1_5 signature over a SHA256 hash.
    /// hash is a 32 bytes long buffer and contains a SHA256 hash value.
    /// output is a buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
    /// signature should be written to output buffer in little-endian format.
    /// This function should return:
    /// - number of bytes written to output on success,
    /// - negative value on failure.
    fn fortanix_edp_crypto_sign_sha256_pkcs1v1_5(rsa_key: *mut c_void, hash: *const c_uchar, output: *mut c_uchar) -> c_int;

    /// Verify an RSASSA-PKCS1-v1_5 signature `sig` over a SHA256 hash.
    /// hash is a 32 bytes long buffer and contains a SHA256 hash value.
    /// sig is a little-endian buffer with RSA key length bytes, e.g. 256 bytes for a 2048 bit key.
    /// This function should return:
    /// - 0 if the signature is verified,
    /// - non-zero on failure.
    fn fortanix_edp_crypto_verify_sha256_pkcs1v1_5(rsa_key: *mut c_void, hash: *const c_uchar, sig: *const c_uchar) -> c_int;
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to parse RSA key, external library returned null pointer.")]
    PemParseFailed,

    #[fail(display = "Failed to {}, external library returned {}.", _0, _1)]
    OperationFailed(&'static str, i32),

    #[fail(display = "Invalid hash size, must be 32 bytes.")]
    InvalidHashSize,

    #[fail(display = "Invalid signature size, must be {} bytes.", _0)]
    InvalidSignatureSize(usize),
}

pub struct PrivateKey {
    pk: *mut c_void,
    len: usize,
}

impl PrivateKey {
    pub fn from_private_key_der(der: &[u8]) -> Result<Self, Error> {
        let pk = unsafe { fortanix_edp_crypto_parse_rsa_private_key_der(der.as_ptr(), der.len() as _) };
        if pk.is_null() {
            return Err(Error::PemParseFailed);
        }
        let len = unsafe { fortanix_edp_crypto_rsa_key_len(pk) } as usize;
        Ok(PrivateKey { pk, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn len_bytes(&self) -> usize {
        (self.len + 7) / 8
    }

    pub fn rsa_modulus(&self) -> Result<Vec<u8>, Error> {
        let mut v = vec![0u8; self.len_bytes()];
        let n = unsafe { fortanix_edp_crypto_rsa_key_modulus(self.pk, v.as_mut_ptr()) };
        if n < 0 {
            return Err(Error::OperationFailed("get RSA modulus", n));
        }
        v.truncate(n as usize);
        Ok(v)
    }

    pub fn rsa_exponent(&self) -> Result<Vec<u8>, Error> {
        let mut v = vec![0u8; self.len_bytes()];
        let n = unsafe { fortanix_edp_crypto_rsa_key_exponent(self.pk, v.as_mut_ptr()) };
        if n < 0 {
            return Err(Error::OperationFailed("get RSA exponent", n));
        }
        v.truncate(n as usize);
        Ok(v)
    }

    pub fn sign_sha256_pkcs1v1_5(&self, hash: &[u8]) -> Result<Vec<u8>, Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidHashSize);
        }
        let mut v = vec![0u8; self.len_bytes()];
        let n = unsafe { fortanix_edp_crypto_sign_sha256_pkcs1v1_5(self.pk, hash.as_ptr(), v.as_mut_ptr()) };
        if n < 0 {
            return Err(Error::OperationFailed("sign", n));
        }
        v.truncate(n as usize);
        Ok(v)
    }

    pub fn verify_sha256_pkcs1v1_5(&self, hash: &[u8], sig: &[u8]) -> Result<(), Error> {
        if hash.len() != 32 {
            return Err(Error::InvalidHashSize);
        }
        if sig.len() != self.len_bytes() {
            return Err(Error::InvalidSignatureSize(self.len_bytes()));
        }
        let r = unsafe { fortanix_edp_crypto_verify_sha256_pkcs1v1_5(self.pk, hash.as_ptr(), sig.as_ptr()) };
        if r != 0 {
            return Err(Error::OperationFailed("verify", r));
        }
        Ok(())
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            fortanix_edp_crypto_free_rsa_key(self.pk);
        }
    }
}

impl AsRef<PrivateKey> for PrivateKey {
    fn as_ref(&self) -> &PrivateKey { self }
}

impl SgxRsaOps for PrivateKey {
    type Error = Compat<Error>;

    fn len(&self) -> usize {
        self.len()
    }

    fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(
        &self,
        hash: H,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Self::Error> {
        let s_vec = PrivateKey::sign_sha256_pkcs1v1_5(self, hash.as_ref()).map_err(Fail::compat)?;

        // Compute Q1 and Q2
        let s = BigUint::from_bytes_le(&s_vec);
        let n = BigUint::from_bytes_le(&self.rsa_modulus().map_err(Fail::compat)?);
        let s_2 = s.clone() * &s;
        let q1 = s_2.clone() / &n;

        let s_3 = s_2 * &s;
        let tmp1 = q1.clone() * &s;
        let tmp2 = tmp1 * &n;
        let tmp3 = s_3 - &tmp2;
        let q2 = tmp3 / &n;

        Ok((s_vec, q1.to_bytes_le(), q2.to_bytes_le()))
    }

    fn verify_sha256_pkcs1v1_5<S: AsRef<[u8]>, H: AsRef<[u8]>>(
        &self,
        sig: S,
        hash: H,
    ) -> Result<(), Self::Error> {
        PrivateKey::verify_sha256_pkcs1v1_5(self, hash.as_ref(), sig.as_ref()).map_err(Fail::compat)
    }

    fn e(&self) -> Vec<u8> {
        self.rsa_exponent().unwrap()
    }

    fn n(&self) -> Vec<u8> {
        self.rsa_modulus().unwrap()
    }
}
