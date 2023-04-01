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

extern crate core;
extern crate rustler;
extern crate serde;
extern crate sui_keys;
mod atoms;
mod options;
mod nif;
// define nif api
rustler::init!(
    "sui_nif",
    [
        nif::new,
        nif::sign
    ],
    load = nif::on_load
);