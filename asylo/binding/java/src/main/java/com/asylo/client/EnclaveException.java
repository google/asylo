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

package com.asylo.client;

/**
 * Exception to represent any error during initialization and execution of enclave  
 */
public class EnclaveException extends RuntimeException {
  private static final long serialVersionUID = -747104125131272523L;

  public EnclaveException() {
    super();
  }

  public EnclaveException(String message) {
    super(message);
  }

  public EnclaveException(String message, Throwable throwable) {
    super(message, throwable);
  }

  public EnclaveException(Throwable throwable) {
    super(throwable);
  }
}
