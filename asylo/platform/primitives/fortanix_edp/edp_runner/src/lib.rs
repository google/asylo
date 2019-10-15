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

extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;
extern crate sgxs;
extern crate failure;
extern crate num_bigint;
extern crate sha2;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use enclave_runner::usercalls::{SyncStream, UsercallExtension};
use sgxs_loaders::isgx::Device as IsgxDevice;
use failure::{Error, ResultExt};
use sha2::Sha256;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::CStr;
use std::io::{ErrorKind, Error as IoError, Result as IoResult, Write};
use std::os::raw::{c_char, c_uchar, c_void};
use std::sync::mpsc::{Sender, Receiver, channel};
use std::sync::Mutex;
use std::{slice, mem, thread};

mod crypto;

use self::crypto::PrivateKey;

pub const ERR_NULL_OUTPUT_PARAM: u64 = 100;
pub const ERR_OTHER: u64 = 101;
pub const ERR_INVALID_ENCLAVE: u64 = 102;

macro_rules! convert_error {
    ( $err:ident, $err_size:ident, $body:expr ) => {{
        match $body {
            Ok(()) => 0,
            Err(e) => {
                if !$err.is_null() {
                    let mut err = slice::from_raw_parts_mut($err, $err_size);
                    write!(err, "{:?}\0", e).expect("failed to copy error message");
                }
                ERR_OTHER
            }
        }
    }}
}

#[no_mangle]
pub unsafe extern "C" fn fortanix_edp_load_enclave(
    path: *const c_char,
    enclave: *mut *mut c_void,
    err: *mut c_uchar,
    err_size: usize,
) -> u64 {
    if enclave.is_null() {
        return ERR_NULL_OUTPUT_PARAM;
    }
    convert_error!(err, err_size, (|| {
        let path = CStr::from_ptr(path).to_str()?;
        match EdpEnclave::load_enclave(path) {
            Ok(edp_enclave) => {
                let edp_enclave = Box::new(edp_enclave);
                *enclave = Box::into_raw(edp_enclave) as _;
                Ok(())
            },
            Err(e) => Err(e)
        }
    })())
}

#[no_mangle]
pub unsafe extern "C" fn fortanix_edp_free_enclave(enclave: *mut c_void) {
    if !enclave.is_null() {
        let _ = Box::from_raw(enclave as *mut EdpEnclave);
    }
}

#[no_mangle]
pub unsafe extern "C" fn fortanix_edp_enclave_call(
    enclave: *mut c_void,
    selector: u64,
    input: *const c_uchar,
    input_size: usize,
    output: *mut *mut c_uchar,
    output_size: *mut usize,
    err: *mut c_uchar,
    err_size: usize,
) -> u64 {
    let enclave = match (enclave as *mut EdpEnclave).as_ref() {
        Some(enclave) => enclave,
        None => return ERR_INVALID_ENCLAVE,
    };
    let input = slice::from_raw_parts(input, input_size);
    convert_error!(err, err_size, (|| {
        match enclave.enclave_call(selector, input) {
            Ok(res) => {
                let res = res.into_boxed_slice();
                *output_size = res.len();
                *output = Box::into_raw(res) as _;
                Ok(())
            },
            Err(e) => Err(e)
        }
    })())
}

#[no_mangle]
pub unsafe extern "C" fn fortanix_edp_free_output_buffer(output: *mut c_uchar, output_size: usize) {
    if !output.is_null() {
        let _ = Box::from_raw(slice::from_raw_parts_mut(output, output_size));
    }
}

#[repr(C)]
pub struct EdpEnclave {
    user_to_enclave_tx: Sender<Vec<u8>>,
    enclave_to_user_rx: Receiver<Vec<u8>>,
    rx_buf: RefCell<VecDeque<u8>>,
    main_thread: thread::JoinHandle<()>,
}

impl EdpEnclave {
    fn load_enclave(path: &str) -> Result<Self, Error> {
        let mut device = IsgxDevice::new()
            .context("While opening SGX device")?
            .einittoken_provider(AesmClient::new())
            .build();
        let mut enclave_builder = EnclaveBuilder::new(path.as_ref());
        enclave_builder.with_dummy_signature_signer::<Sha256, _, _, _, _>(|der| {
            PrivateKey::from_private_key_der(der).unwrap()
        });

        let (user_to_enclave_tx, user_to_enclave_rx) = channel();
        let (enclave_to_user_tx, enclave_to_user_rx) = channel();
        let asylo_extension = AsyloExtension {
            inner: Mutex::new(Some(MessageStream::new(enclave_to_user_tx, user_to_enclave_rx))),
        };
        enclave_builder.usercall_extension(asylo_extension);

        let enclave = enclave_builder.build(&mut device).context("While loading SGX enclave")?;
        let main_thread = thread::spawn(move || {
            enclave.run().map_err(|e| {
                println!("Error while executing SGX enclave.\n{}", e);
                std::process::exit(1);
            }).unwrap();
        });
        Ok(Self { user_to_enclave_tx, enclave_to_user_rx, rx_buf: RefCell::new(VecDeque::new()), main_thread })
    }

    fn read_exact(&self, len: usize) -> Result<Vec<u8>, Error> {
        let mut rx_buf = self.rx_buf.borrow_mut();
        while rx_buf.len() < len {
            rx_buf.extend(self.enclave_to_user_rx.recv()?.into_iter());
        }
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(rx_buf.pop_front().unwrap());
        }
        Ok(v)
    }

    fn enclave_call(&self, selector: u64, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut msg = Vec::with_capacity(16 + input.len());
        msg.extend_from_slice(&selector.to_be_bytes());
        msg.extend_from_slice(&input.len().to_be_bytes());
        msg.extend_from_slice(input);
        self.user_to_enclave_tx.send(msg)?;

        let size = self.read_exact(mem::size_of::<usize>())?;
        let mut s = [0u8; mem::size_of::<usize>()];
        s.copy_from_slice(&size);
        let size = usize::from_be_bytes(s);

        self.read_exact(size)
    }
}

#[derive(Debug)]
struct MessageStreamRecv {
    rx: Receiver<Vec<u8>>,
    rx_buf: Vec<u8>,
}

#[derive(Debug)]
struct MessageStream {
    tx: Mutex<Sender<Vec<u8>>>,
    rx: Mutex<MessageStreamRecv>,
}

impl MessageStream {
    fn new(tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>>) -> Self {
        MessageStream {
            tx: Mutex::new(tx),
            rx: Mutex::new(MessageStreamRecv { rx, rx_buf: Vec::new() }),
        }
    }
}

impl SyncStream for MessageStream {
    fn read(&self, mut buf: &mut [u8]) -> IoResult<usize> {
        let mut inner = self.rx.lock().unwrap();
        if inner.rx_buf.is_empty() {
            inner.rx_buf = inner.rx.recv().map_err(|_| IoError::new(ErrorKind::BrokenPipe, "Channel was closed"))?;
        }
        let n = buf.write(&inner.rx_buf).unwrap();
        if n > 0 {
            inner.rx_buf.drain(0..n);
        }
        return Ok(n);
    }

    fn write(&self, buf: &[u8]) -> IoResult<usize> {
        let tx = self.tx.lock().unwrap();
        tx.send(buf.to_owned()).map_err(|_| IoError::new(ErrorKind::BrokenPipe, "Channel was closed"))?;
        Ok(buf.len())
    }

    fn flush(&self) -> IoResult<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct AsyloExtension {
    inner: Mutex<Option<MessageStream>>,
}

impl UsercallExtension for AsyloExtension {
    fn connect_stream(
        &self,
        addr: &str,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncStream>>> {
        match &*addr {
            "asylo-enclave-server" => {
                if let Some(local_addr) = local_addr {
                    *local_addr = "0.0.0.0:0".to_owned();
                }
                if let Some(peer_addr) = peer_addr {
                    *peer_addr = "0.0.0.0:0".to_owned();
                }
                self.inner.lock().unwrap()
                    .take()
                    .map(|stream| Box::new(stream))
                    .map_or(Err(IoError::new(ErrorKind::ConnectionRefused, "Connection refused")), |s| Ok(Some(s)))
            }
            _ => Ok(None),
        }
    }
}
