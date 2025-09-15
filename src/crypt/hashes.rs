use alloy::{ 
    consensus::crypto::secp256k1::sign_message, 
    primitives::{FixedBytes, Keccak256, B256}, 
    signers::Signature,
};
use k256::{ecdsa::{SigningKey}};

use crate::utils::errors::{Errors, WalletResult};

pub fn derive_socialz_msg_hash(message: &[u8]) -> FixedBytes<32> {
    let prefix = format!("\x13Socialz Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher.finalize()
}

pub fn socialz_sign_msg(signing_key: &SigningKey, message: &[u8]) 
    -> WalletResult<(Signature,B256)> 
{
    let fixed_key = FixedBytes::from_slice(signing_key.to_bytes().as_slice());
    let hash = derive_socialz_msg_hash(message);
    let sig = sign_message(fixed_key, hash).map_err(|e| Errors::SignMsg(e.to_string()))?;
    Ok((sig,hash))
}
