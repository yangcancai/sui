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

#[macro_use]
extern crate bencher;
use bencher::Bencher;

fn get(bench: &mut Bencher) {
	bench.iter(|| {
	    assert_eq!(get_word(""),"".to_string());
	});
    }
fn get_word(str: &str) -> String{
	    str.to_string()
}
benchmark_group!(benches, get);
benchmark_main!(benches);
