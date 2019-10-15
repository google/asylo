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

use crate::proto::status;

pub enum ErrorSpace {
    Google,
}

impl ErrorSpace {
    pub fn name(&self) -> &'static str {
        match *self {
            ErrorSpace::Google => "::asylo::error::GoogleErrorSpace",
        }
    }
}

pub enum GoogleError {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

#[derive(Debug, Clone)]
pub struct Status(status::StatusProto);

impl Status {
    pub fn ok() -> Self {
        Self::new(ErrorSpace::Google, 0, None)
    }

    pub fn new(space: ErrorSpace, code: i32, message: Option<String>) -> Self {
        let mut s = status::StatusProto::new();
        s.set_space(space.name().to_owned());
        s.set_code(code);
        s.set_canonical_code(code);
        if let Some(msg) = message {
            s.set_error_message(msg);
        }
        Self(s)
    }

    pub fn error(code: GoogleError, message: Option<String>) -> Self {
        Self::new(ErrorSpace::Google, code as i32, message)
    }

    pub(crate) fn protobuf_message(&self) -> &status::StatusProto {
        &self.0
    }
}
