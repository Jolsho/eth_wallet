use std::{sync::Arc};

use argon2::Argon2;
use bip32::{ DerivationPath, XPrv };
use chacha20poly1305::Key;
use k256::{ecdsa::{SigningKey}};

use crate::{
    crypt::{self, cha}, 
    utils::errors::{Errors, WalletResult},
};

mod cache;
pub mod db;
pub mod store;

#[derive(Clone)]
pub enum KeyType {
    ETH(SigningKey),
    SZ(SigningKey),
    Cha(chacha20poly1305::Key),
}
impl KeyType {
    pub fn as_signing(&self) -> WalletResult<&SigningKey> {
        match self {
            KeyType::ETH(key) | KeyType::SZ(key) => Ok(key),
            _ => Err(Errors::InvalidKeyType),
        }
    }

    pub fn as_chacha(&self) -> WalletResult<&Key> {
        match self {
            KeyType::Cha(key) => Ok(key),
            _ => Err(Errors::InvalidKeyType),
        }
    }
}

const ETH_DER_PATH: &'static str = "m/44'/60'/0'/0/";
const SZ_DER_PATH: &'static str = "m/44'/696969'/0'/0/";

pub fn new_eth_key(idx: i64, seed: &[u8;64]) -> 
    WalletResult<bip32::ExtendedPrivateKey<SigningKey>> 
{
    let derivation_path = eth_path(idx);
    XPrv::derive_from_path(seed, &derivation_path)
        .map_err(|e| Errors::GenerateErr(e.to_string()))
}
fn eth_path(idx: i64) -> DerivationPath {
    let der = format!("{}{}", ETH_DER_PATH, idx);
    der.parse::<DerivationPath>().unwrap()
}

#[allow(unused)]
pub fn new_sz_key(idx: i64, seed: &[u8;64]) -> 
    WalletResult<bip32::ExtendedPrivateKey<SigningKey>> 
{
    let derivation_path = socialz_path(idx);
    XPrv::derive_from_path(seed, &derivation_path)
        .map_err(|e| Errors::GenerateErr(e.to_string()))
}

fn socialz_path(idx: i64) -> DerivationPath {
    let der = format!("{}{}", SZ_DER_PATH, idx);
    der.parse::<DerivationPath>().unwrap()
}

pub fn derive_argon_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Key derivation failed");
    key
}

pub async fn get_key<F>(
    store: &store::KeyStore, uid: &str,
    kid: &str, table: String, master: &Key,
    make_key: F,
) -> WalletResult<Arc<KeyType>>
where
    F: FnOnce(Vec<u8>) -> WalletResult<KeyType>,
{
    if let Some(key_entry) = store.keys.get(kid).await {
        Ok(key_entry.key.clone())
    } else {
        let (enc_raw_key,nonce) = store.db.get_key(table, uid, kid).await?;
        let raw_key = cha::decrypt(master, nonce, &enc_raw_key.to_vec())?;
        let key = make_key(raw_key)?;
        store.keys.put(kid, key.clone()).await;
        Ok(Arc::new(key))
    }
}

pub async fn new_ecc_key<FF,F>(
    store: &store::KeyStore, 
    uid: &str, table: String, 
    make_raw_key: FF,
    make_key_type: F,
) -> WalletResult<Arc<KeyType>>
where
    FF: FnOnce(i64,&[u8; 64]) -> WalletResult<bip32::ExtendedPrivateKey<SigningKey>>,
    F: FnOnce(SigningKey) -> WalletResult<KeyType>
{
    if let Some((idx,meta)) = store.masters.get_idx_seed_master(uid, &table).await {
        let xprv = make_raw_key(idx, &meta.seed)?;
        let key = xprv.private_key();

        let addr = crypt::derive_address(key.verifying_key());
        let (nonce, enc_key) = cha::encrypt(&meta.master, &key.to_bytes())
            .map_err(|e| Errors::FailedEncKey(e.to_string()))?;

        store.db.put_key(table, uid, addr.to_vec(), nonce, enc_key).await?;

        let real_key = make_key_type(key.clone())?;
        store.keys.put(&addr.to_string(), real_key.clone()).await;

        Ok(Arc::new(real_key))
    } else {
        Err(Errors::NoMetaData)
    }
}
