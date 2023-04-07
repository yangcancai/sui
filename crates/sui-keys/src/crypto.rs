// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use derive_more::From;
use fastcrypto::bls12381::min_sig::{
    BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
    BLS12381PrivateKey, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::error::FastCryptoError;
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::secp256r1::{Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature};
pub use fastcrypto::traits::KeyPair as KeypairTraits;
pub use fastcrypto::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, SigningKey, ToFromBytes,
    VerifyingKey,
};
 
use schemars::JsonSchema;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::hash::{Hash};
use std::str::FromStr;
use crate::base_types::SuiAddress;
use crate::sui_error::{SuiError};
use fastcrypto::encoding::{Base64, Encoding};
use std::fmt::{Debug, Formatter};
pub use enum_dispatch::enum_dispatch;
use crate::base_types::Readable;
pub use fastcrypto::traits::Signer;
use serde_with::Bytes;
use serde::Deserializer;
use eyre::eyre;
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
  pub fn as_vec(&self) -> Vec<u8> {
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
        bytes
    }

}
impl FromStr for SuiKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}
impl EncodeDecodeBase64 for SuiKeyPair {
    /// Encode a SuiKeyPair as `flag || privkey` in Base64. Note that the pubkey is not encoded.
    fn encode_base64(&self) -> String {
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

    /// Decode a SuiKeyPair from `flag || privkey` in Base64. The public key is computed directly from the private key bytes.
    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode(value).map_err(|e| eyre!("{}", e.to_string()))?;
        match SignatureScheme::from_flag_byte(bytes.first().ok_or_else(|| eyre!("Invalid length"))?)
        {
            Ok(x) => match x {
                SignatureScheme::ED25519 => Ok(SuiKeyPair::Ed25519(Ed25519KeyPair::from_bytes(
                    bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                )?)),
                SignatureScheme::Secp256k1 => {
                    Ok(SuiKeyPair::Secp256k1(Secp256k1KeyPair::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?))
                }
                SignatureScheme::Secp256r1 => {
                    Ok(SuiKeyPair::Secp256r1(Secp256r1KeyPair::from_bytes(
                        bytes.get(1..).ok_or_else(|| eyre!("Invalid length"))?,
                    )?))
                }
                _ => Err(eyre!("Invalid flag byte")),
            },
            _ => Err(eyre!("Invalid bytes")),
        }
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

impl<'de> Deserialize<'de> for SuiKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        <SuiKeyPair as EncodeDecodeBase64>::decode_base64(&s)
            .map_err(|e| Error::custom(e.to_string()))
    }
}



pub trait SuiPublicKey: VerifyingKey {
    const SIGNATURE_SCHEME: SignatureScheme;
}
#[enum_dispatch(Signature)]
pub trait SuiSignature: Sized + ToFromBytes {
    fn signature_bytes(&self) -> &[u8];
    fn public_key_bytes(&self) -> &[u8];
    fn scheme(&self) -> SignatureScheme;

    // fn verify<T>(&self, value: &T, author: SuiAddress) -> SuiResult<()>
    // where
    //     T: Signable<Vec<u8>>;

    // fn verify_secure<T>(&self, value: &IntentMessage<T>, author: SuiAddress) -> SuiResult<()>
    // where
    //     T: Serialize;
}
impl<S: SuiSignatureInner + Sized> SuiSignature for S {
    fn signature_bytes(&self) -> &[u8] {
        // Access array slice is safe because the array bytes is initialized as
        // flag || signature || pubkey with its defined length.
        &self.as_ref()[1..1 + S::Sig::LENGTH]
    }

    fn public_key_bytes(&self) -> &[u8] {
        // Access array slice is safe because the array bytes is initialized as
        // flag || signature || pubkey with its defined length.
        &self.as_ref()[S::Sig::LENGTH + 1..]
    }

    fn scheme(&self) -> SignatureScheme {
        S::PubKey::SIGNATURE_SCHEME
    }
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

impl Signer<Signature> for SuiKeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            SuiKeyPair::Ed25519(kp) => kp.sign(msg),
            SuiKeyPair::Secp256k1(kp) => kp.sign(msg),
            SuiKeyPair::Secp256r1(kp) => kp.sign(msg),
        }
    }
}
//
// Account Signatures
//

// Enums for signature scheme signatures
#[enum_dispatch]
#[derive(Clone, JsonSchema, PartialEq, Eq, Hash)]
pub enum Signature {
    Ed25519SuiSignature,
    Secp256k1SuiSignature,
    Secp256r1SuiSignature,
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref();

        if serializer.is_human_readable() {
            let s = Base64::encode(bytes);
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_bytes(bytes)
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Base64::decode(&s).map_err(|e| Error::custom(e.to_string()))?
        } else {
            let data: Vec<u8> = Vec::deserialize(deserializer)?;
            data
        };

        Self::from_bytes(&bytes).map_err(|e| Error::custom(e.to_string()))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ed25519SuiSignature(sig) => sig.as_ref(),
            Signature::Secp256k1SuiSignature(sig) => sig.as_ref(),
            Signature::Secp256r1SuiSignature(sig) => sig.as_ref(),
        }
    }
}
impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Signature::Ed25519SuiSignature(sig) => sig.as_mut(),
            Signature::Secp256k1SuiSignature(sig) => sig.as_mut(),
            Signature::Secp256r1SuiSignature(sig) => sig.as_mut(),
        }
    }
}

impl ToFromBytes for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match bytes.first() {
            Some(x) => {
                if x == &Ed25519SuiSignature::SCHEME.flag() {
                    Ok(<Ed25519SuiSignature as ToFromBytes>::from_bytes(bytes)
                        .map_err(|_| signature::Error::new())?
                        .into())
                } else if x == &Secp256k1SuiSignature::SCHEME.flag() {
                    Ok(<Secp256k1SuiSignature as ToFromBytes>::from_bytes(bytes)
                        .map_err(|_| signature::Error::new())?
                        .into())
                } else if x == &Secp256r1SuiSignature::SCHEME.flag() {
                    Ok(<Secp256r1SuiSignature as ToFromBytes>::from_bytes(bytes)
                        .map_err(|_| signature::Error::new())?
                        .into())
                } else {
                    Err(FastCryptoError::InvalidInput)
                }
            }
            _ => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let flag = Base64::encode([self.scheme().flag()]);
        let s = Base64::encode(self.signature_bytes());
        let p = Base64::encode(self.public_key_bytes());
        write!(f, "{flag}@{s}@{p}")?;
        Ok(())
    }
}
impl Signature{
    pub fn signatures(&self) -> Vec<String>{
       let flag = Base64::encode([self.scheme().flag()]);
        let s = Base64::encode(self.signature_bytes());
        let p = Base64::encode(self.public_key_bytes());
        vec![flag, s, p]
    }
}

//
// BLS Port
//

impl SuiPublicKey for BLS12381PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::BLS12381;
}

//
// Ed25519 Sui Signature port
//

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Ed25519SuiSignature(
    #[schemars(with = "Base64")]
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1],
);

// Implementation useful for simplify testing when mock signature is needed
impl Default for Ed25519SuiSignature {
    fn default() -> Self {
        Self([0; Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1])
    }
}

impl SuiSignatureInner for Ed25519SuiSignature {
    type Sig = Ed25519Signature;
    type PubKey = Ed25519PublicKey;
    type KeyPair = Ed25519KeyPair;
    const LENGTH: usize = Ed25519PublicKey::LENGTH + Ed25519Signature::LENGTH + 1;
}

impl SuiPublicKey for Ed25519PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;
}

impl AsRef<[u8]> for Ed25519SuiSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Ed25519SuiSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl ToFromBytes for Ed25519SuiSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(FastCryptoError::InputLengthWrong(Self::LENGTH));
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl Signer<Signature> for Ed25519KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        Ed25519SuiSignature::new(self, msg).into()
    }
}

//
// Secp256k1 Sui Signature port
//
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Secp256k1SuiSignature(
    #[schemars(with = "Base64")]
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1],
);

impl SuiSignatureInner for Secp256k1SuiSignature {
    type Sig = Secp256k1Signature;
    type PubKey = Secp256k1PublicKey;
    type KeyPair = Secp256k1KeyPair;
    const LENGTH: usize = Secp256k1PublicKey::LENGTH + Secp256k1Signature::LENGTH + 1;
}

impl SuiPublicKey for Secp256k1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256k1;
}

impl AsRef<[u8]> for Secp256k1SuiSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Secp256k1SuiSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl ToFromBytes for Secp256k1SuiSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(FastCryptoError::InputLengthWrong(Self::LENGTH));
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl Signer<Signature> for Secp256k1KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        Secp256k1SuiSignature::new(self, msg).into()
    }
}

//
// Secp256r1 Sui Signature port
//
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Secp256r1SuiSignature(
    #[schemars(with = "Base64")]
    #[serde_as(as = "Readable<Base64, Bytes>")]
    [u8; Secp256r1PublicKey::LENGTH + Secp256r1Signature::LENGTH + 1],
);

impl SuiSignatureInner for Secp256r1SuiSignature {
    type Sig = Secp256r1Signature;
    type PubKey = Secp256r1PublicKey;
    type KeyPair = Secp256r1KeyPair;
    const LENGTH: usize = Secp256r1PublicKey::LENGTH + Secp256r1Signature::LENGTH + 1;
}

impl SuiPublicKey for Secp256r1PublicKey {
    const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::Secp256r1;
}

impl AsRef<[u8]> for Secp256r1SuiSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Secp256r1SuiSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl ToFromBytes for Secp256r1SuiSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != Self::LENGTH {
            return Err(FastCryptoError::InputLengthWrong(Self::LENGTH));
        }
        let mut sig_bytes = [0; Self::LENGTH];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self(sig_bytes))
    }
}

impl Signer<Signature> for Secp256r1KeyPair {
    fn sign(&self, msg: &[u8]) -> Signature {
        Secp256r1SuiSignature::new(self, msg).into()
    }
}


//
// This struct exists due to the limitations of the `enum_dispatch` library.
//
pub trait SuiSignatureInner: Sized + ToFromBytes + PartialEq + Eq + Hash {
    type Sig: Authenticator<PubKey = Self::PubKey>;
    type PubKey: VerifyingKey<Sig = Self::Sig> + SuiPublicKey;
    type KeyPair: KeypairTraits<PubKey = Self::PubKey, Sig = Self::Sig>;

    const LENGTH: usize = Self::Sig::LENGTH + Self::PubKey::LENGTH + 1;
    const SCHEME: SignatureScheme = Self::PubKey::SIGNATURE_SCHEME;

    // fn get_verification_inputs(&self, author: SuiAddress) -> SuiResult<(Self::Sig, Self::PubKey)> {
    //     // Is this signature emitted by the expected author?
    //     let bytes = self.public_key_bytes();
    //     let pk = Self::PubKey::from_bytes(bytes)
    //         .map_err(|_| SuiError::KeyConversionError("Invalid public key".to_string()))?;

    //     let received_addr = SuiAddress::from(&pk);
    //     if received_addr != author {
    //         return Err(SuiError::IncorrectSigner {
    //             error: format!("Signature get_verification_inputs() failure. Author is {author}, received address is {received_addr}")
    //         });
    //     }

    //     // deserialize the signature
    //     let signature = Self::Sig::from_bytes(self.signature_bytes()).map_err(|err| {
    //         SuiError::InvalidSignature {
    //             error: err.to_string(),
    //         }
    //     })?;

    //     Ok((signature, pk))
    // }

    fn new(kp: &Self::KeyPair, message: &[u8]) -> Self {
        let sig = Signer::sign(kp, message);

        let mut signature_bytes: Vec<u8> = Vec::new();
        signature_bytes
            .extend_from_slice(&[<Self::PubKey as SuiPublicKey>::SIGNATURE_SCHEME.flag()]);
        signature_bytes.extend_from_slice(sig.as_ref());
        signature_bytes.extend_from_slice(kp.public().as_ref());
        Self::from_bytes(&signature_bytes[..])
            .expect("Serialized signature did not have expected size")
    }
}
pub fn sign(tx_bytes: &[u8], secret: &str) -> Result<Vec<String>, eyre::Report>{
    let keypair = SuiKeyPair::decode_base64(secret)?;
    let signature = keypair.sign(tx_bytes);
     Ok(signature.signatures())
}
pub fn account_detail(secret: &str) -> Result<(Vec<u8>, String, Vec<u8>, String),eyre::Report>{
    let keypair = SuiKeyPair::decode_base64(secret)?;
    let addr = SuiAddress::from(&keypair);
    Ok((addr.to_vec(), String::from(&addr), keypair.as_vec(), secret.into()))
}
pub fn decode_pub(public: &str) -> Result<Vec<u8>, eyre::Report>{
    let addr: SuiAddress= SuiAddress::decode(&public[2..])?;
    Ok(addr.to_vec())
}