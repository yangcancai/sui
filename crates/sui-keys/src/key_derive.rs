// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use bip32::{ChildNumber, DerivationPath, Mnemonic, XPrv};

use crate::base_types::SuiAddress;
use crate::crypto::{SignatureScheme, SuiKeyPair};
use crate::sui_error::SuiError;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::{
    ed25519::Ed25519PrivateKey,
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey},
    traits::{KeyPair, ToFromBytes},
};
use fastcrypto::encoding::Hex;
use fastcrypto::encoding::Encoding;

use signature::rand_core::OsRng;
use slip10_ed25519::derive_ed25519_private_key;

pub const DERIVATION_PATH_COIN_TYPE: u32 = 784;
pub const DERVIATION_PATH_PURPOSE_ED25519: u32 = 44;
pub const DERVIATION_PATH_PURPOSE_SECP256K1: u32 = 54;
pub const DERVIATION_PATH_PURPOSE_SECP256R1: u32 = 74;

/// Ed25519 follows SLIP-0010 using hardened path: m/44'/784'/0'/0'/{index}'
/// Secp256k1 follows BIP-32/44 using path where the first 3 levels are hardened: m/54'/784'/0'/0/{index}
/// Secp256r1 follows BIP-32/44 using path where the first 3 levels are hardened: m/74'/784'/0'/0/{index}
/// Note that the purpose node is used to distinguish signature schemes.
pub fn derive_key_pair_from_path(
    seed: &[u8],
    derivation_path: Option<DerivationPath>,
    key_scheme: &SignatureScheme,
) -> Result<(SuiAddress, SuiKeyPair), SuiError> {
    let path = validate_path(key_scheme, derivation_path)?;
    match key_scheme {
        SignatureScheme::ED25519 => {
            let indexes = path.into_iter().map(|i| i.into()).collect::<Vec<_>>();
            let derived = derive_ed25519_private_key(seed, &indexes);
            let sk = Ed25519PrivateKey::from_bytes(&derived)
                .map_err(|e| SuiError::SignatureKeyGenError(e.to_string()))?;
            let kp: Ed25519KeyPair = sk.into();
            Ok((kp.public().into(), SuiKeyPair::Ed25519(kp)))
        }
        SignatureScheme::Secp256k1 => {
            let child_xprv = XPrv::derive_from_path(seed, &path)
                .map_err(|e| SuiError::SignatureKeyGenError(e.to_string()))?;
            let kp = Secp256k1KeyPair::from(
                Secp256k1PrivateKey::from_bytes(child_xprv.private_key().to_bytes().as_slice())
                    .map_err(|e| SuiError::SignatureKeyGenError(e.to_string()))?,
            );
            Ok((kp.public().into(), SuiKeyPair::Secp256k1(kp)))
        }
        // SignatureScheme::Secp256r1 => {
        //     let child_xprv = XPrv::derive_from_path(seed, &path)
        //         .map_err(|e| SuiError::SignatureKeyGenError(e.to_string()))?;
        //     let kp = Secp256r1KeyPair::from(
        //         Secp256r1PrivateKey::from_bytes(child_xprv.private_key().to_bytes().as_slice())
        //             .map_err(|e| SuiError::SignatureKeyGenError(e.to_string()))?,
        //     );
        //     Ok((kp.public().into(), SuiKeyPair::Secp256r1(kp)))
        // }
        SignatureScheme::BLS12381 | SignatureScheme::MultiSig | SignatureScheme::Secp256r1 => {
            Err(SuiError::UnsupportedFeatureError {
                error: format!("key derivation not supported {:?}", key_scheme),
            })
        }
    }
}

pub fn validate_path(
    key_scheme: &SignatureScheme,
    path: Option<DerivationPath>,
) -> Result<DerivationPath, SuiError> {
    match key_scheme {
        SignatureScheme::ED25519 => {
            match path {
                Some(p) => {
                    // The derivation path must be hardened at all levels with purpose = 44, coin_type = 784
                    if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                        if Some(purpose)
                            == ChildNumber::new(DERVIATION_PATH_PURPOSE_ED25519, true).ok()
                            && Some(coin_type)
                                == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                            && account.is_hardened()
                            && change.is_hardened()
                            && address.is_hardened()
                        {
                            Ok(p)
                        } else {
                            Err(SuiError::SignatureKeyGenError("Invalid path".to_string()))
                        }
                    } else {
                        Err(SuiError::SignatureKeyGenError("Invalid path".to_string()))
                    }
                }
                None => Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_ED25519}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0'/0'"
                )
                .parse()
                .map_err(|_| SuiError::SignatureKeyGenError("Cannot parse path".to_string()))?),
            }
        }
        SignatureScheme::Secp256k1 => {
            match path {
                Some(p) => {
                    // The derivation path must be hardened at first 3 levels with purpose = 54, coin_type = 784
                    if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                        if Some(purpose)
                            == ChildNumber::new(DERVIATION_PATH_PURPOSE_SECP256K1, true).ok()
                            && Some(coin_type)
                                == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                            && account.is_hardened()
                            && !change.is_hardened()
                            && !address.is_hardened()
                        {
                            Ok(p)
                        } else {
                            Err(SuiError::SignatureKeyGenError("Invalid path".to_string()))
                        }
                    } else {
                        Err(SuiError::SignatureKeyGenError("Invalid path".to_string()))
                    }
                }
                None => Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_SECP256K1}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0/0"
                )
                .parse()
                .map_err(|_| SuiError::SignatureKeyGenError("Cannot parse path".to_string()))?),
            }
        }
        SignatureScheme::Secp256r1 => {
            match path {
                Some(p) => {
                    // The derivation path must be hardened at first 3 levels with purpose = 74, coin_type = 784
                    if let &[purpose, coin_type, account, change, address] = p.as_ref() {
                        if Some(purpose)
                            == ChildNumber::new(DERVIATION_PATH_PURPOSE_SECP256R1, true).ok()
                            && Some(coin_type)
                                == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).ok()
                            && account.is_hardened()
                            && !change.is_hardened()
                            && !address.is_hardened()
                        {
                            Ok(p)
                        } else {
                            Err(SuiError::SignatureKeyGenError("Invalid path".to_string()))
                        }
                    } else {
                        Err(SuiError::SignatureKeyGenError("Invalid path".to_string()))
                    }
                }
                None => Ok(format!(
                    "m/{DERVIATION_PATH_PURPOSE_SECP256K1}'/{DERIVATION_PATH_COIN_TYPE}'/0'/0/0"
                )
                .parse()
                .map_err(|_| SuiError::SignatureKeyGenError("Cannot parse path".to_string()))?),
            }
        }
        SignatureScheme::BLS12381 | SignatureScheme::MultiSig => {
            Err(SuiError::UnsupportedFeatureError {
                error: format!("key derivation not supported {:?}", key_scheme),
            })
        }
    }
}

pub fn generate_new_key1(
    key_scheme: SignatureScheme,
    derivation_path: Option<DerivationPath>,
) -> Result<(String, String, String, String), anyhow::Error> {
    let mnemonic = Mnemonic::random(OsRng, Default::default());
    let seed = mnemonic.to_seed("");
    match derive_key_pair_from_path(seed.as_bytes(), derivation_path, &key_scheme) {
        Ok((address, kp)) => Ok((format!("0x{}",Hex::encode(address)), kp.encode_base64(), key_scheme.to_string(), mnemonic.phrase().to_string())),
        Err(e) => Err(anyhow!("Failed to generate keypair: {:?}", e)),
    }
}
pub fn generate_new_key(
    key_scheme: SignatureScheme,
    derivation_path: Option<DerivationPath>,
) -> Result<(SuiAddress, SuiKeyPair, SignatureScheme, String), anyhow::Error> {
    let mnemonic = Mnemonic::random(OsRng, Default::default());
    let seed = mnemonic.to_seed("");
    match derive_key_pair_from_path(seed.as_bytes(), derivation_path, &key_scheme) {
        Ok((address, kp)) => Ok((address, kp, key_scheme, mnemonic.phrase().to_string())),
        Err(e) => Err(anyhow!("Failed to generate keypair: {:?}", e)),
    }
}
