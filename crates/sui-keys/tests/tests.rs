use std::vec;

use sui_keys::crypto::{sign, SuiKeyPair, EncodeDecodeBase64, Signer, SuiSignature};
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
    let secret = "AKpjfApmHx8FbjrRRSrUlF6ITigjP8NMS1ip4JdqPp5g";
    // let keypair = SuiKeyPair::decode_base64(secret).unwrap();
    // let signature = keypair.sign(b"hello");
    // assert_eq!(signature.signature_bytes(), b"kk");
    let res = sign(b"hello", secret).unwrap();
    assert_eq!(res, vec!["AE+1/eSxZaEh2sBGmPf5ur+yYwv8hmZCUjloMI7hyHASyOKZnZUGdrTgttpv0/Sbo63FzJ/bDf4ckCNp3pXmoAAI/6lQ7vrLtz33uzNjy1UUvx+JwK1WRWVuFnUg7DkNew=="]);
}
