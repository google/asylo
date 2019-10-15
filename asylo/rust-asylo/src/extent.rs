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

use std::mem;

pub struct ExtentIterator<'a>(&'a [u8]);

impl<'a> ExtentIterator<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self(input)
    }
}

impl<'a> Iterator for ExtentIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() == 0 {
            return None;
        }
        if self.0.len() < mem::size_of::<usize>() {
            panic!("invalid buffer state, has < 8 bytes left");
        }
        let mut len = [0u8; mem::size_of::<usize>()];
        len.copy_from_slice(&self.0[0..mem::size_of::<usize>()]);
        let len = usize::from_le_bytes(len);

        if self.0.len() < mem::size_of::<usize>() + len {
            panic!("invalid buffer state, has < 8 + len bytes left");
        }
        let (_, s) = self.0.split_at(mem::size_of::<usize>());
        let (s, rem) = s.split_at(len);
        self.0 = rem;
        Some(s)
    }
}

pub struct ExtentWriter(Vec<u8>);

impl ExtentWriter {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn write_extent(&mut self, extent: &[u8]) {
        self.0.reserve(mem::size_of::<usize>() + extent.len());
        self.0.extend_from_slice(&extent.len().to_le_bytes());
        self.0.extend_from_slice(extent);
    }

    pub fn write_protobuf_message<T: protobuf::Message>(&mut self, msg: &T) {
        let mut output = Vec::new();
        msg.write_to_vec(&mut output).expect("failed to serialize protobuf message");
        self.write_extent(&output);
    }

    pub fn finalize(self) -> Vec<u8> {
        self.0
    }
}
