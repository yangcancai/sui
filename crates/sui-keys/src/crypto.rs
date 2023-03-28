// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use derive_more::From;
use fastcrypto::bls12381::min_sig::{
    BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
    BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey};
use fastcrypto::secp256r1::{Secp256r1KeyPair, Secp256r1PublicKey};
pub use fastcrypto::traits::KeyPair as KeypairTraits;
pub use fastcrypto::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, SigningKey, ToFromBytes,
    VerifyingKey,
};
use schemars::JsonSchema;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::base_types::SuiAddress;
use crate::sui_error::SuiError;
use fastcrypto::encoding::{Base64, Encoding};
use std::fmt::Debug;

pub use fastcrypto::traits::Signer;

// Authority Objects
pub type AuthorityKeyPair = BLS12381KeyPair;
pub type AuthorityPublicKey = BLS12381PublicKey;
pub type AuthorityPrivateKey = BLS12381PrivateKey;
pub type AuthoritySignature = BLS12381Signature;
pub type AggregateAuthoritySignature = BLS12381AggregateSignature;
pub type AggregateAuthoritySignatureAsBytes = BLS12381AggregateSignatureAsBytes;

// TODO(joyqvq): prefix these types with Default, DefaultAccountKeyPair etc
pub type AccountKeyPair = Ed25519KeyPair;
pub type AccountPublicKey = Ed25519PublicKey;
pub type AccountPrivateKey = Ed25519PrivateKey;
pub type AccountSignature = Ed25519Signature;

pub type NetworkKeyPair = Ed25519KeyPair;
pub type NetworkPublicKey = Ed25519PublicKey;
pub type NetworkPrivateKey = Ed25519PrivateKey;

pub const PROOF_OF_POSSESSION_DOMAIN: &[u8] = b"kosk";
pub const DERIVATION_PATH_COIN_TYPE: u32 = 784;
pub const DERVIATION_PATH_PURPOSE_ED25519: u32 = 44;
pub const DERVIATION_PATH_PURPOSE_SECP256K1: u32 = 54;
pub const TBLS_RANDOMNESS_OBJECT_DOMAIN: &[u8; 10] = b"randomness";

// Creates a proof that the keypair is possesed, as well as binds this proof to a specific SuiAddress.
pub fn generate_proof_of_possession<K: KeypairTraits>(
    keypair: &K,
    address: SuiAddress,
) -> <K as KeypairTraits>::Sig {
    let mut domain_with_pk: Vec<u8> = Vec::new();
    domain_with_pk.extend_from_slice(PROOF_OF_POSSESSION_DOMAIN);
    domain_with_pk.extend_from_slice(keypair.public().as_bytes());
    domain_with_pk.extend_from_slice(address.as_ref());
    // TODO (joyqvq): Use Signature::new_secure
    keypair.sign(&domain_with_pk[..])
}

///////////////////////////////////////////////
/// Account Keys
///
/// * The following section defines the keypairs that are used by
/// * accounts to interact with Sui.
/// * Currently we support eddsa and ecdsa on Sui.
///

#[allow(clippy::large_enum_variant)]
#[derive(Debug, From, PartialEq, Eq)]
pub enum SuiKeyPair {
    Ed25519(Ed25519KeyPair),
    Secp256k1(Secp256k1KeyPair),
    Secp256r1(Secp256r1KeyPair),
}

#[derive(Clone, PartialEq, Eq, From, JsonSchema)]
pub enum PublicKey {
    #[schemars(with = "Base64")]
    Ed25519(Ed25519PublicKey),
    #[schemars(with = "Base64")]
    Secp256k1(Secp256k1PublicKey),
    #[schemars(with = "Base64")]
    Secp256r1(Secp256r1PublicKey),
}

impl PublicKey {
    pub fn flag(&self) -> u8 {
        match self {
            PublicKey::Ed25519(_) => SignatureScheme::ED25519.flag(),
            PublicKey::Secp256k1(_) => SignatureScheme::Secp256k1.flag(),
            PublicKey::Secp256r1(_) => SignatureScheme::Secp256r1.flag(),
        }
    }
}
impl SuiKeyPair {
    pub fn public(&self) -> PublicKey {
        match self {
            SuiKeyPair::Ed25519(kp) => PublicKey::Ed25519(kp.public().clone()),
            SuiKeyPair::Secp256k1(kp) => PublicKey::Secp256k1(kp.public().clone()),
            SuiKeyPair::Secp256r1(kp) => PublicKey::Secp256r1(kp.public().clone()),
        }
    }
}
impl SuiKeyPair {
    /// Encode a SuiKeyPair as `flag || privkey` in Base64. Note that the pubkey is not encoded.
    pub fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        match self {
            SuiKeyPair::Ed25519(kp) => {
                bytes.push(self.public().flag());
                bytes.extend_from_slice(kp.as_bytes());
            }
            SuiKeyPair::Secp256k1(kp) => {
                bytes.push(self.public().flag());
                bytes.extend_from_slice(kp.as_bytes());
            }
            SuiKeyPair::Secp256r1(kp) => {
                bytes.push(self.public().flag());
                bytes.extend_from_slice(kp.as_bytes());
            }
        }
        Base64::encode(&bytes[..])
    }
}

impl Serialize for SuiKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = self.encode_base64();
        serializer.serialize_str(&s)
    }
}

// impl<'de> Deserialize<'de> for SuiKeyPair {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         use serde::de::Error;
//         let s = String::deserialize(deserializer)?;
//         <SuiKeyPair as EncodeDecodeBase64>::decode_base64(&s)
//             .map_err(|e| Error::custom(e.to_string()))
//     }
// }

pub trait SuiPublicKey: VerifyingKey {
    const SIGNATURE_SCHEME: SignatureScheme;
}

#[derive(Deserialize, Serialize, JsonSchema, Debug, strum_macros::Display)]
#[strum(serialize_all = "lowercase")]
pub enum SignatureScheme {
    ED25519,
    Secp256k1,
    Secp256r1,
    BLS12381,
    MultiSig,
}
#[allow(clippy::should_implement_trait)]
impl SignatureScheme {
    pub fn flag(&self) -> u8 {
        match self {
            SignatureScheme::ED25519 => 0x00,
            SignatureScheme::Secp256k1 => 0x01,
            SignatureScheme::Secp256r1 => 0x02,
            SignatureScheme::MultiSig => 0x03,
            SignatureScheme::BLS12381 => 0xff,
        }
    }
    pub fn from_str(name: &str) -> Result<SignatureScheme, SuiError> {
        match name.to_lowercase().as_str() {
            "ed25519" => Ok(SignatureScheme::ED25519),
            "secp256k1" => Ok(SignatureScheme::Secp256k1),
            "secp256r1" => Ok(SignatureScheme::Secp256r1),
            "multiig" => Ok(SignatureScheme::MultiSig),
            "bls12381" => Ok(SignatureScheme::BLS12381),
            _ => Err(SuiError::KeyConversionError(
                "Invalid key scheme".to_string(),
            )),
        }
    }

    pub fn from_flag(flag: &str) -> Result<SignatureScheme, SuiError> {
        let byte_int = flag
            .parse::<u8>()
            .map_err(|_| SuiError::KeyConversionError("Invalid key scheme".to_string()))?;
        Self::from_flag_byte(&byte_int)
    }

    pub fn from_flag_byte(byte_int: &u8) -> Result<SignatureScheme, SuiError> {
        match byte_int {
            0x00 => Ok(SignatureScheme::ED25519),
            0x01 => Ok(SignatureScheme::Secp256k1),
            0x02 => Ok(SignatureScheme::Secp256r1),
            0x03 => Ok(SignatureScheme::MultiSig),
            _ => Err(SuiError::KeyConversionError(
                "Invalid key scheme".to_string(),
            )),
        }
    }
}
