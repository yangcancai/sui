// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::secp256k1::Secp256k1PublicKey;
use fastcrypto::secp256r1::Secp256r1PublicKey;
use rand::Rng;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;
use serde_with::{DeserializeAs, SerializeAs};
use crate::crypto::{SignatureScheme};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::hash::{HashFunction, Sha3_256};

pub const SUI_ADDRESS_LENGTH: usize = 20;
use schemars::JsonSchema;
// use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(
    Eq, Default, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct SuiAddress(
    #[schemars(with = "Hex")]
    #[serde_as(as = "Readable<Hex, _>")]
    [u8; SUI_ADDRESS_LENGTH],
);
#[allow(clippy::wrong_self_convention)]
impl SuiAddress {
    pub const ZERO: Self = Self([0u8; SUI_ADDRESS_LENGTH]);

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    // for testing
    pub fn random_for_testing_only() -> Self {
        let random_bytes = rand::thread_rng().gen::<[u8; SUI_ADDRESS_LENGTH]>();
        Self(random_bytes)
    }

    pub fn optional_address_as_hex<S>(
        key: &Option<SuiAddress>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&key.map(Hex::encode).unwrap_or_default())
    }
    pub fn to_inner(self) -> [u8; SUI_ADDRESS_LENGTH] {
        self.0
    }
}

impl From<&Ed25519PublicKey> for SuiAddress {
    fn from(pk: &Ed25519PublicKey) -> Self {
        let mut hasher = Sha3_256::default();
        hasher.update([SignatureScheme::ED25519.flag()]);
        hasher.update(pk);
        let g_arr = hasher.finalize();

        let mut res = [0u8; SUI_ADDRESS_LENGTH];
        // OK to access slice because Sha3_256 should never be shorter than SUI_ADDRESS_LENGTH.
        res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..SUI_ADDRESS_LENGTH]);
        SuiAddress(res)
    }
}

impl From<&Secp256k1PublicKey> for SuiAddress {
    fn from(pk: &Secp256k1PublicKey) -> Self {
        let mut hasher = Sha3_256::default();
        hasher.update([SignatureScheme::Secp256k1.flag()]);
        hasher.update(pk);
        let g_arr = hasher.finalize();

        let mut res = [0u8; SUI_ADDRESS_LENGTH];
        // OK to access slice because Sha3_256 should never be shorter than SUI_ADDRESS_LENGTH.
        res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..SUI_ADDRESS_LENGTH]);
        SuiAddress(res)
    }
}

impl From<&Secp256r1PublicKey> for SuiAddress {
    fn from(pk: &Secp256r1PublicKey) -> Self {
        let mut hasher = Sha3_256::default();
        hasher.update([SignatureScheme::Secp256r1.flag()]);
        hasher.update(pk);
        let g_arr = hasher.finalize();

        let mut res = [0u8; SUI_ADDRESS_LENGTH];
        // OK to access slice because Sha3_256 should never be shorter than SUI_ADDRESS_LENGTH.
        res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..SUI_ADDRESS_LENGTH]);
        SuiAddress(res)
    }
}
// impl<T: SuiPublicKey> From<&T> for SuiAddress {
//     fn from(pk: &T) -> Self {
//         let mut hasher = Sha3_256::default();
//         hasher.update([T::SIGNATURE_SCHEME.flag()]);
//         hasher.update(pk);
//         let g_arr = hasher.finalize();

//         let mut res = [0u8; SUI_ADDRESS_LENGTH];
//         // OK to access slice because Sha3_256 should never be shorter than SUI_ADDRESS_LENGTH.
//         res.copy_from_slice(&AsRef::<[u8]>::as_ref(&g_arr)[..SUI_ADDRESS_LENGTH]);
//         SuiAddress(res)
//     }
// }

impl AsRef<[u8]> for SuiAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Use with serde_as to encode/decode bytes to/from Base64/Hex for human-readable serializer and deserializer
/// E : Encoding of the human readable output
/// R : serde_as SerializeAs/DeserializeAs delegation
///
/// # Example:
///
/// ```text
/// #[serde_as]
/// #[derive(Deserialize, Serialize)]
/// struct Example(#[serde_as(as = "Readable(Hex, _)")] [u8; 20]);
/// ```
///
/// The above example will encode the byte array to Hex string for human-readable serializer
/// and array tuple (default) for non-human-readable serializer.
pub struct Readable<E, R> {
    element: PhantomData<R>,
    encoding: PhantomData<E>,
}

impl<T, R, E> SerializeAs<T> for Readable<E, R>
where
    T: AsRef<[u8]>,
    R: SerializeAs<T>,
    E: SerializeAs<T>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            E::serialize_as(value, serializer)
        } else {
            R::serialize_as(value, serializer)
        }
    }
}
/// DeserializeAs support for Arrays
impl<'de, R, E, const N: usize> DeserializeAs<'de, [u8; N]> for Readable<E, R>
where
    R: DeserializeAs<'de, [u8; N]>,
    E: DeserializeAs<'de, Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = E::deserialize_as(deserializer)?;
            if value.len() != N {
                return Err(Error::custom(anyhow!(
                    "invalid array length {}, expecting {}",
                    value.len(),
                    N
                )));
            }
            let mut array = [0u8; N];
            array.copy_from_slice(&value[..N]);
            Ok(array)
        } else {
            R::deserialize_as(deserializer)
        }
    }
}
/// DeserializeAs support for Vec
impl<'de, R, E> DeserializeAs<'de, Vec<u8>> for Readable<E, R>
where
    R: DeserializeAs<'de, Vec<u8>>,
    E: DeserializeAs<'de, Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            E::deserialize_as(deserializer)
        } else {
            R::deserialize_as(deserializer)
        }
    }
}
