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

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"log"
	"github.com/golang/crypto/curve25519"
	"github.com/golang/crypto/hkdf"
)

var (
	// Curve25519 test vector taken from https://tools.ietf.org/html/rfc7748#page-14.
	pubKey = [32]byte{0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
		0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
		0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
		0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f}

	privKey = [32]byte{0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
		0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a}

	// EKEP transcript hash. This is the SHA256 hash of the input message "abc",
	// as taken from https://www.di-mgt.com.au/sha_testvectors.html.
	info = [32]byte{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
)

// deriveSecrets generates an EKEP primary and authenticator secret using
// Curve25519 and SHA256.
func deriveSecrets() ([]byte, []byte) {
	// Compute the shared secret.
	var secret [32]byte
	curve25519.ScalarMult(&secret, &privKey, &pubKey)
	hash := sha256.New
	salt := []byte("EKEP Handshake v1")
	hkdf := hkdf.New(hash, secret[:], salt, info[:])

	// Generate the primary and authenticator secrets.
	primarySecret := make([]byte, 64)
	authSecret := make([]byte, 64)

	n, err := io.ReadFull(hkdf, primarySecret)
	if n != len(primarySecret) || err != nil {
		log.Fatalf("io.ReadFull(%v, %v) = _, %v", hkdf, primarySecret, err)
	}

	n, err = io.ReadFull(hkdf, authSecret)
	if n != len(authSecret) || err != nil {
		log.Fatalf("io.ReadFull(%v, %v) = _, %v", hkdf, authSecret, err)
	}
	return primarySecret, authSecret
}

// DeriveRecordProtocolKey generates an ALTSRP AES128 GCM record protocol key
// using the given primary secret.
func deriveRecordProtocolKey(primarySecret []byte) []byte {
	hash := sha256.New
	salt := []byte("EKEP Record Protocol v1")
	hkdf := hkdf.New(hash, primarySecret, salt, info[:])
	key := make([]byte, 16)

	n, err := io.ReadFull(hkdf, key)
	if n != len(key) || err != nil {
		log.Fatalf("io.ReadFull(%v, %v) = _, %v", hkdf, key, err)
	}
	return key
}

// HmacSha256 generates an message authentication code using SHA256 as the
// underlying hash function.
func hmacSha256(key, input []byte) []byte {
	hash := sha256.New
	hmac := hmac.New(hash, key)

	// Writing to a Hash function never returns an error
	hmac.Write(input)

	return hmac.Sum(nil)
}

// ComputeServerHandshakeAuthenticator computes the EKEP server handshake
// authenticator using the given authenticator secret.
func computeServerHandshakeAuthenticator(authenticatorSecret []byte) []byte {
	input := []byte("EKEP Handshake v1: Server Finish")
	return hmacSha256(authenticatorSecret, input)
}

// ComputeClientHandshakeAuthenticator computes the EKEP client handshake
// authenticator using the given authenticator secret.
func computeClientHandshakeAuthenticator(authenticatorSecret []byte) []byte {
	input := []byte("EKEP Handshake v1: Client Finish")
	return hmacSha256(authenticatorSecret, input)
}

func main() {
	// EKEP primary and authenticator secrets
	primarySecret, authSecret := deriveSecrets()

	fmt.Println(">>EKEP Secret Derivation<<")
	fmt.Printf("Public key:\n%s\n", hex.EncodeToString(pubKey[:]))
	fmt.Printf("Private key:\n%s\n", hex.EncodeToString(privKey[:]))
	fmt.Printf("HKDF info:\n%s\n", hex.EncodeToString(info[:]))
	fmt.Printf("Primary secret:\n%s\n", hex.EncodeToString(primarySecret))
	fmt.Printf("Authenticator secret:\n%s\n\n", hex.EncodeToString(authSecret))

	// EKEP record protocol secrets
	key := deriveRecordProtocolKey(primarySecret)

	fmt.Println(">>EKEP Record Protocol Key<<")
	fmt.Printf("Primary secret:\n%s\n", hex.EncodeToString(primarySecret[:]))
	fmt.Printf("HKDF info:\n%s\n", hex.EncodeToString(info[:]))
	fmt.Printf("Record protocol key:\n%s\n\n", hex.EncodeToString(key[:]))

	// EKEP server handshake authenticator
	serverAuthn := computeServerHandshakeAuthenticator(authSecret)

	fmt.Println(">>EKEP Server Handshake Authenticator<<")
	fmt.Printf("Authenticator secret:\n%s\n", hex.EncodeToString(authSecret))
	fmt.Printf("Server handshake authenticator:\n%s\n\n", hex.EncodeToString(serverAuthn))

	// EKEP client handshake authenticator
	clientAuthn := computeClientHandshakeAuthenticator(authSecret)

	fmt.Println(">>EKEP Client Handshake Authenticator<<")
	fmt.Printf("Authenticator secret:\n%s\n", hex.EncodeToString(authSecret))
	fmt.Printf("Client handshake authenticator:\n%s\n\n", hex.EncodeToString(clientAuthn))
}
