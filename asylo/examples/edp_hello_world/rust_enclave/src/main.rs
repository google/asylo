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

use asylo::{self, Status, EnclaveConfig, EnclaveInput, EnclaveOutput, EnclaveFinal};

include!(concat!(env!("OUT_DIR"), "/mod_hello_proto.rs"));

use hello::{exts, HelloOutput};
use protobuf::Message;

struct HelloApplication {
    visitor_count: u32
}

impl asylo::TrustedApplication for HelloApplication {
    fn initialize(_config: EnclaveConfig) -> Result<Self, Status> {
        return Ok(HelloApplication{
            visitor_count: 0
        })
    }

    fn run(&mut self, input: EnclaveInput, output: Option<&mut EnclaveOutput>) -> Status {
        let hello_input = match exts::enclave_input_hello.get(&input) {
            Some(hello_input) => hello_input,
            None => return Status::error(
                asylo::GoogleError::InvalidArgument,
                Some("Expected a HelloInput extension on input.".to_owned()),
            )
        };
        let visitor = hello_input.get_to_greet();
        println!("Hello {}", visitor);
        self.visitor_count += 1;
        if let Some(output) = output {
            let mut hello_output = HelloOutput::new();
            hello_output.set_greeting_message(
                format!("Hello {}, you are visitor # {}", visitor, self.visitor_count)
            );
            // FIXME: it appears that protobuf Rust crate does not provide a way to set
            // message extensions, hence the following hack
            let v = hello_output.write_to_bytes().expect("failed to serialize hello output");
            output.mut_unknown_fields().add_length_delimited(8087, v);
        }
        return Status::ok()
    }

    fn finalize(self, _final_input: EnclaveFinal) -> Status {
        return Status::ok()
    }
}

fn main() {
    asylo::run::<HelloApplication>().unwrap();
}
