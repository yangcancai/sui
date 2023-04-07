use std::vec;

use sui_keys::crypto::sign;
use sui_keys::key_derive::generate_new_key;
use sui_keys::{crypto::SignatureScheme};
use sui_keys::base_types::SuiAddress;

#[test]
fn gen() {
    let a = SignatureScheme::from_str("Ed25519");
    assert_eq!(a.unwrap().to_string(), "ed25519");
     let (a,b,_c,d)= generate_new_key(SignatureScheme::ED25519, None).unwrap();
     let a_str = serde_json::to_string(&a).unwrap();
     let b_str = serde_json::to_string(&b).unwrap();
     print!("{:?}, {}, b:{}", a.as_ref(), a_str, b_str);
     let c: SuiAddress = SuiAddress::from(&b);
     assert_eq!(String::from(&a), String::from(&c));
}
#[test]
fn sign_test(){
    let res = sign(b"hello", "AJSL4uYRFyzwyC7cfAWQiBVwtXXQHZfp2ALuxaomxXgq").unwrap();
    assert_eq!(res, vec!["AA==", "LFxG0+eRjJ2U/tuT/7TR4mCAMsguF9Nemt8ZaVW+tlvtYPJiiQXjqjbYpIhmZBcAuySbF8/XBRzerAQhdBt5Dg==", "jZITPZUimFhgH28FQ0QUAY1uhXEHzC/EqZ4wnjZbJeA="]);
}
