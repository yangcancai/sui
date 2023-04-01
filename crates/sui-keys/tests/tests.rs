use std::vec;

use sui_keys::crypto::sign;
use sui_keys::{crypto::SignatureScheme};

#[test]
fn gen() {
    let a = SignatureScheme::from_str("Ed25519");
    assert_eq!(a.unwrap().to_string(), "ed25519");
    // let (a,b,_c,d)= generate_new_key(SignatureScheme::ED25519, None).unwrap();
    // let a_str = serde_json::to_string(&a).unwrap();
    // let b_str = serde_json::to_string(&b).unwrap();
    // print!("{:?}, {}, b:{}", a.as_ref(), a_str, b_str);
    // assert_eq!(a_str, Hex::encode(a));
}
#[test]
fn sign_test(){
    let res = sign(b"hello", "AJSL4uYRFyzwyC7cfAWQiBVwtXXQHZfp2ALuxaomxXgq").unwrap();
    assert_eq!(res, vec!["AA==", "LFxG0+eRjJ2U/tuT/7TR4mCAMsguF9Nemt8ZaVW+tlvtYPJiiQXjqjbYpIhmZBcAuySbF8/XBRzerAQhdBt5Dg==", "jZITPZUimFhgH28FQ0QUAY1uhXEHzC/EqZ4wnjZbJeA="]);
}
