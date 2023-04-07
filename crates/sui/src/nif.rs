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

use rustler::{Binary, Encoder, Env, NifResult, OwnedBinary, Term};
use std::borrow::Cow;
use atoms::{ok,error};
use options::NifsuiOptions;
use sui_keys::{crypto::SignatureScheme, key_derive::generate_new_key1};
// =================================================================================================
// resource
// =================================================================================================
pub fn on_load(_env: Env, _load_info: Term) -> bool {
    true
}

// =================================================================================================
// api
// =================================================================================================

#[rustler::nif]
fn new<'a>(env: Env<'a>, opts: NifsuiOptions) -> NifResult<Term<'a>> {
    match SignatureScheme::from_str(opts.key_schema.as_str()){
        Ok(key_schema) => {
            match generate_new_key1(key_schema, None) {
                Ok((a, b, c, d)) => {
                    Ok((ok(), (a, b, c, d)).encode(env))
                },
                Err(_e) => { Ok(error().encode(env)) }
            }
        }
        Err(_e) => { Ok(error().encode(env)) }
        }
}
fn u8_to_string(msg: &[u8]) -> String{
    let a = String::from_utf8_lossy(msg);
    match a{
        Cow::Owned(own_msg) => own_msg,
        Cow::Borrowed(b_msg) => b_msg.to_string()
    }
}
#[rustler::nif]
fn sign<'a>(env: Env<'a>, tx_bytes: LazyBinary<'a>, secret: LazyBinary<'a>) -> NifResult<Term<'a>> {
   match sui_keys::crypto::sign(&tx_bytes, u8_to_string(&secret).as_str()){
       Ok(res) =>{
           Ok((ok(), res).encode(env))
       },
       Err(_e) => { Ok(error().encode(env)) }
   }
}
#[rustler::nif]
fn account_detail<'a>(env: Env<'a>, key: LazyBinary<'a>) -> NifResult<Term<'a>> {
   match sui_keys::crypto::account_detail(u8_to_string(&key).as_str()){
       Ok((bin_public, public, bin_secret, secret)) =>{
           Ok((ok(), (u8_to_string(&bin_public), public, u8_to_string(&bin_secret), secret)).encode(env))
       },
       Err(_e) => { Ok(error().encode(env)) }
   }
}
#[rustler::nif]
fn decode_pub<'a>(env: Env<'a>, public: LazyBinary<'a>) -> NifResult<Term<'a>> {
   match sui_keys::crypto::decode_pub(u8_to_string(&public).as_str()){
       Ok(res) =>{
           Ok((ok(), u8_to_string(&res)).encode(env))
       },
       Err(_e) => { Ok(error().encode(env)) }
   }
}
// =================================================================================================
// helpers
// =================================================================================================

/// Represents either a borrowed `Binary` or `OwnedBinary`.
///
/// `LazyBinary` allows for the most efficient conversion from an
/// Erlang term to a byte slice. If the term is an actual Erlang
/// binary, constructing `LazyBinary` is essentially
/// zero-cost. However, if the term is any other Erlang type, it is
/// converted to an `OwnedBinary`, which requires a heap allocation.
enum LazyBinary<'a> {
    Owned(OwnedBinary),
    Borrowed(Binary<'a>),
}

impl<'a> std::ops::Deref for LazyBinary<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(owned) => owned.as_ref(),
            Self::Borrowed(borrowed) => borrowed.as_ref(),
        }
    }
}

impl<'a> rustler::Decoder<'a> for LazyBinary<'a> {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        if term.is_binary() {
            Ok(Self::Borrowed(Binary::from_term(term)?))
        } else {
            Ok(Self::Owned(term.to_binary()))
        }
    }
}
