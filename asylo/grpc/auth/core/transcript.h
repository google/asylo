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

#ifndef ASYLO_GRPC_AUTH_CORE_TRANSCRIPT_H_
#define ASYLO_GRPC_AUTH_CORE_TRANSCRIPT_H_

#include <cstdlib>
#include <memory>
#include <string>

#include <google/protobuf/io/zero_copy_stream.h>
#include "asylo/crypto/hash_interface.h"

namespace asylo {

// Transcript maintains a running hash of an EKEP (Enclave Key Exchange
// Protocol) transcript. An EKEP transcript is a hash of the concatenation of
// all EKEP frames sent in an EKEP session. Due to the nature of the protocol,
// the ciphersuite is unknown to both the client and server until after several
// frames have already been exchanged between the participants. Therefore, it is
// necessary to save these earlier frames in their raw form until the
// ciphersuite has been determined. This class provides the functionality
// necessary for caching earlier frames and delaying the hashing operation until
// a hashing function is set.
//
// A Transcript can be updated via the Add method. The hash of the current
// transcript can be retrieved through a call to Hash. Before calling Hash, it
// is necessary to first set the hash function for the transcript via the
// SetHasher method.
//
// This class is not thread-safe.
class Transcript {
 public:
  Transcript() = default;
  Transcript(const Transcript &) = delete;
  Transcript &operator=(const Transcript &) = delete;

  // Adds the entire contents of |input| to the transcript hash.
  void Add(google::protobuf::io::ZeroCopyInputStream *input);

  // Sets |hasher| as the hash function to use for hashing the transcript.
  // Returns false if a hash function has already been set. Takes ownership of
  // |hasher|.
  bool SetHasher(HashInterface *hasher);

  // Sets |digest| to a string containing a hash of the current transcript.
  // Returns false if the hash function for this transcript has not yet been set
  // through a call to SetHasher.
  bool Hash(std::string *digest);

 private:
  // Adds |len| bytes from |data| to the transcript hash.
  void Add(const void *data, size_t len);

  // An internal buffer of bytes to hash. Once |hasher_| is set, all bytes from
  // this buffer are added to the hashing object and the buffer is cleared.
  std::string bytes_to_hash_;

  // The hash function used to hash the transcript.
  std::unique_ptr<HashInterface> hasher_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_TRANSCRIPT_H_
