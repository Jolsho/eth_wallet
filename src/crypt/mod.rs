pub mod hashes;
pub mod eip55;
pub mod cha;

use k256::{ecdsa::{VerifyingKey}};
use rand::{rngs, TryRngCore};
use alloy::primitives::{Address, Keccak256};

pub fn derive_address(key: &VerifyingKey) -> Address {
    let pubkey_uncompressed = key.to_encoded_point(false);
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_uncompressed.as_bytes()[1..]);
    let hash = hasher.finalize();
    Address::from_slice(&hash[12..])
}

pub fn get_random(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rngs::OsRng.try_fill_bytes(&mut buf).unwrap();
    buf
}
