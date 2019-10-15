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

use std::{env, io};
use std::net::TcpStream;
use std::mem;
use crate::extent::*;
use super::*;

pub fn run<T: TrustedApplication>() -> Result<(), io::Error> {
    let mut stream = TcpStream::connect("asylo-enclave-server")?;
    let mut app = None;
    loop {
        let (selector, input) = read_next_message(&mut stream)?;
        let input = ExtentIterator::new(&input);
        let mut output = ExtentWriter::new();

        let finish = match Selector::from_u64(selector) {
            Some(Selector::Initialize) => {
                app = handle_initialize::<T>(input, &mut output)?;
                false
            }
            Some(Selector::Run) => {
                handle_run(input, &mut output, app.as_mut().unwrap())?;
                false
            }
            Some(Selector::Finalize) => {
                handle_finalize(input, &mut output, app.take().unwrap())?;
                true
            }
            None => {
                println!("Unrecognized selector: {}", selector);
                true
            }
        };
        write_next_response(&mut stream, &output.finalize())?;
        if finish {
            break;
        }
    }
    Ok(())
}

fn handle_initialize<T: TrustedApplication>(
    mut input: ExtentIterator,
    output: &mut ExtentWriter,
) -> Result<Option<T>, io::Error> {

    let config = input.next().unwrap();
    let _name = input.next().unwrap();

    let config: EnclaveConfig = parse_protobuf(config)?;
    for ev in config.get_environment_variables() {
        env::set_var(ev.get_name(), ev.get_value());
    }

    let (status, app) = match T::initialize(config) {
        Ok(app) => (Status::ok(), Some(app)),
        Err(err) => (err, None),
    };
    output.write_protobuf_message(status.protobuf_message());
    Ok(app)
}

fn handle_run<T: TrustedApplication>(
    mut input: ExtentIterator,
    output: &mut ExtentWriter,
    app: &mut T,
) -> Result<(), io::Error> {

    let enclave_input = input.next().unwrap();

    let enclave_input: EnclaveInput = parse_protobuf(enclave_input)?;
    let mut enclave_output = EnclaveOutput::new();
    let status = app.run(enclave_input, Some(&mut enclave_output));
    enclave_output.set_status(status.protobuf_message().to_owned());

    output.write_protobuf_message(&enclave_output);
    Ok(())
}

fn handle_finalize<T: TrustedApplication>(
    mut input: ExtentIterator,
    output: &mut ExtentWriter,
    app: T,
) -> Result<(), io::Error> {

    let final_input = input.next().unwrap();

    let final_input: EnclaveFinal = parse_protobuf(final_input)?;
    let status = app.finalize(final_input);

    output.write_protobuf_message(status.protobuf_message());
    Ok(())
}


fn read_next_message<S: io::Read>(stream: &mut S) -> Result<(u64, Vec<u8>), io::Error> {
    let mut header = [0u8; mem::size_of::<u64>() + mem::size_of::<usize>()];
    stream.read_exact(&mut header)?;

    let mut selector = [0u8; mem::size_of::<u64>()];
    selector.copy_from_slice(&header[0..mem::size_of::<u64>()]);
    let selector = u64::from_be_bytes(selector);

    let mut len = [0u8; mem::size_of::<usize>()];
    len.copy_from_slice(&header[mem::size_of::<u64>()..]);
    let len = usize::from_be_bytes(len);

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok((selector, body))
}

fn write_next_response<S: io::Write>(stream: &mut S, response: &[u8]) -> Result<(), io::Error> {
    stream.write_all(&response.len().to_be_bytes())?;
    stream.write_all(response)?;
    Ok(())
}

enum Selector {
    Initialize,
    Run,
    Finalize,
}

impl Selector {
    fn from_u64(selector: u64) -> Option<Self> {
        // Reference:
        // - asylo/platform/core/entry_selectors.h
        // - asylo/platform/primitives/primitives.h line 60
        match selector {
            128 => Some(Selector::Initialize),
            129 => Some(Selector::Run),
            130 => Some(Selector::Finalize),
            _ => None,
        }
    }
}

fn parse_protobuf<T: protobuf::Message>(buf: &[u8]) -> io::Result<T> {
    protobuf::parse_from_bytes::<T>(buf).map_err(|_| io::Error::new(
        io::ErrorKind::Other, "failed to parse protobuf message"
    ))
}
