use sui_keys::{crypto::SignatureScheme, key_derive::generate_new_key};
use fastcrypto::encoding::Hex;
use fastcrypto::encoding::Encoding;

#[test]
fn gen() {
    let a = SignatureScheme::from_str("Ed25519");
    assert_eq!(a.unwrap().to_string(), "ed25519");
    let (a,b,_c,d)= generate_new_key(SignatureScheme::ED25519, None).unwrap();
    let a_str = serde_json::to_string(&a).unwrap();
    let b_str = serde_json::to_string(&b).unwrap();
    print!("{:?}, {}, b:{}", a.as_ref(), a_str, b_str);
    // assert_eq!(a_str, Hex::encode(a));
}
