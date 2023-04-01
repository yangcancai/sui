use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, IntoStaticStr};
use thiserror::Error;

// pub type SuiResult<T = ()> = Result<T, SuiError>;
/// Custom error type for Sui.
#[derive(
    Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Error, Hash, AsRefStr, IntoStaticStr,
)]
#[allow(clippy::large_enum_variant)]
pub enum SuiError {
    #[error("Use of disabled feature: {:?}", error)]
    UnsupportedFeatureError { error: String },
    #[error("Signature key generation error: {0}")]
    SignatureKeyGenError(String),
    // Object misuse issues
    #[error("Error checking transaction input objects: {:?}", errors)]
    TransactionInputObjectsErrors { errors: Vec<SuiError> },
    #[error("Attempt to transfer an object that's not owned.")]
    TransferUnownedError,
    #[error("Attempt to transfer an object that does not have public transfer. Object transfer must be done instead using a distinct Move function call.")]
    TransferObjectWithoutPublicTransferError,
    #[error("The SUI coin to be transferred has balance {balance}, which is not enough to cover the transfer amount {required}")]
    TransferInsufficientBalance { balance: u64, required: u64 },
    #[error("Expecting a singler owner, shared ownership found")]
    UnexpectedOwnerType,
    #[error("Shared object not yet supported")]
    UnsupportedSharedObjectError,
    #[error("Object used as shared is not shared.")]
    NotSharedObjectError,
    #[error("An object that's owned by another object cannot be deleted or wrapped. It must be transferred to an account address first before deletion")]
    DeleteObjectOwnedObject,
    #[error("Key Conversion Error: {0}")]
    KeyConversionError(String),
}
