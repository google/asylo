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

mod error;
mod extent;
pub mod proto;
mod runtime;

pub use self::error::*;
pub use self::runtime::run;
pub use self::proto::enclave::{EnclaveConfig, EnclaveInput, EnclaveOutput, EnclaveFinal};

pub trait TrustedApplication: Sized {
    fn initialize(config: EnclaveConfig) -> Result<Self, Status>;
    fn run(&mut self, input: EnclaveInput, output: Option<&mut EnclaveOutput>) -> Status;
    fn finalize(self, final_input: EnclaveFinal) -> Status;
}
