//-------------------------------------------------------------------
// @author Cam

// Copyright (c) 2021 by Cam(yangcancai0112@gmail.com), All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
   
// @doc
//
// @end
// Created : 2023-03-26T09:08:05+00:00
//-------------------------------------------------------------------

use rustler::{Decoder, NifResult, Term};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct NifsuiOptions {
    pub key_schema: String,
    pub path: Option<String>,
}

impl Default for NifsuiOptions {
    fn default() -> NifsuiOptions {
        NifsuiOptions {
            key_schema: "ed25519".into(),
            path: None
        }
    }
}

impl<'a> Decoder<'a> for NifsuiOptions {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let mut opts = Self::default();
        use rustler::{Error, MapIterator};
        for (key, value) in MapIterator::new(term).ok_or(Error::BadArg)? {
            match key.atom_to_string()?.as_ref() {
                "key_schema" => opts.key_schema = value.decode()?,
                "path" => opts.path = Some(value.decode()?),
                _ => (),
            }
        }
        Ok(opts)
    }
}
