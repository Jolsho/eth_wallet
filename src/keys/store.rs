use std::{ 
    str::FromStr, sync::Arc, time::Duration 
};
use alloy::primitives::Address;
use bip39::Mnemonic;
use chacha20poly1305::Key;
use k256::{ecdsa::SigningKey};
use crate::{
    crypt::{self, cha}, 
    keys::{
        self, cache::{self, Idxs}, db::{self, CHA_TABLE, ETH_TABLE, SZ_TABLE}, new_ecc_key, KeyType 
    },
    utils::{self, errors::{Errors, WalletResult}},
};

pub struct KeyStore {
    pub keys: cache::KeyCache,
    pub masters: cache::MasterCache,
    pub db: db::KeyDB,
} 

impl KeyStore { 
    pub fn new(db: utils::db::DB) -> Result<Arc<Self>, deadpool_sqlite::rusqlite::Error> {
        Ok(Arc::new(Self { 
            db: db,
            keys: cache::KeyCache::new(Duration::new(10, 0),100),
            masters: cache::MasterCache::new(Duration::new(10,0),100)
        }))
    }

    pub async fn load_masters(&self, uid: &str, pword: &str) -> WalletResult<()> {

        let (m_salt, enc_mnemon, mn_nonce, socialz, ether) = self.db.get_masters(uid).await?;
        let raw_master = keys::derive_argon_key(pword, &m_salt);
        let master = Key::from_slice(&raw_master);

        let mnem = crypt::cha::decrypt(&master, mn_nonce, &enc_mnemon)?;

        let m = String::from_utf8(mnem)
            .map_err(|e|Errors::MnemonErr(e.to_string()))?;

        let mnem = Mnemonic::from_str(&m)
            .map_err(|e|Errors::MnemonErr(e.to_string()))?;

        let seed = mnem.to_seed(pword);

        let entry = (Idxs{socialz,ether}, *master, seed);
        self.masters.put(uid, entry).await;
        Ok(())
    }

    pub async fn get_eth_key(&self, uid: &str, kid: &str) -> WalletResult<Arc<KeyType>> {
        if let Some(e) = self.masters.get(uid).await {
            keys::get_key(self, uid, kid, ETH_TABLE.to_string(), &e.master, |raw_key|  {
                let key = SigningKey::from_slice(&raw_key)
                    .map_err(|e| Errors::FromSlice(e.to_string()))?;
                Ok(KeyType::ETH(key))
            }).await
        } else {
            Err(Errors::NoMetaData)
        }
    }

    pub async fn get_sz_key(&self, uid: &str, kid: &str) -> WalletResult<Arc<KeyType>> {
        if let Some(e) = self.masters.get(uid).await {
            keys::get_key(self, uid, kid, SZ_TABLE.to_string(), &e.master, |raw_key|  {
                let key = SigningKey::from_slice(&raw_key)
                    .map_err(|e| Errors::FromSlice(e.to_string()))?;
                Ok(KeyType::SZ(key))
            }).await
        } else {
            Err(Errors::NoMetaData)
        }
    }


    pub async fn get_cha_key(&self, uid: &str, kid: &str)  -> WalletResult<Arc<KeyType>> {
        if let Some(e) = self.masters.get(uid).await {
            keys::get_key(self, uid, kid, CHA_TABLE.to_string(), &e.master, |raw_key| 
                Ok(KeyType::Cha(*Key::from_slice(&raw_key)))
            ).await
        } else {
            Err(Errors::NoMetaData)
        }
    }

    pub async fn put_eth_key(&self, uid: &str, addr: Address, key: SigningKey) 
        -> WalletResult<Arc<KeyType>> 
    {
        if let Some(e) = self.masters.get(uid).await {
            let (nonce, enc_key) = cha::encrypt(&e.master, &key.to_bytes())
                .map_err(|e| Errors::FailedEncKey(e.to_string()))?;

            self.db.put_key(ETH_TABLE.to_string(), uid, addr.to_vec(), nonce, enc_key).await
                .map_err(|e| Errors::FailedPut(e.to_string()))?;

            let key_type = KeyType::ETH(key);
            self.keys.put(&addr.to_string(), key_type.clone()).await;
            Ok(Arc::new(key_type))
        } else {
            Err(Errors::NoMetaData)
        }
    }


    pub async fn put_sz_key(&self, uid: &str, addr: Address, key: SigningKey) 
        -> WalletResult<Arc<KeyType>> 
    {
        if let Some(e) = self.masters.get(uid).await {
            let (nonce, enc_key) = cha::encrypt(&e.master, &key.to_bytes())
                .map_err(|e| Errors::FailedEncKey(e.to_string()))?;

            self.db.put_key(ETH_TABLE.to_string(), uid, addr.to_vec(), nonce, enc_key).await
                .map_err(|e| Errors::FailedPut(e.to_string()))?;

            let key_type = KeyType::ETH(key);
            self.keys.put(&addr.to_string(), key_type.clone()).await;
            Ok(Arc::new(key_type))
        } else {
            Err(Errors::NoMetaData)
        }
    }


    pub async fn new_eth_key(&self, uid: &str) -> WalletResult<Arc<KeyType>> {
        new_ecc_key(self, uid, ETH_TABLE.to_string(), keys::new_eth_key, 
            |key| Ok(KeyType::ETH(key))
        ).await
    }

    pub async fn new_sz_key(&self, uid: &str) ->  WalletResult<Arc<KeyType>> {
        new_ecc_key(self, uid, SZ_TABLE.to_string(), keys::new_sz_key, 
            |key| Ok(KeyType::SZ(key))
        ).await
    }

    pub async fn new_cha_key(&self, uid: &str, id_str: &str) -> WalletResult<Arc<KeyType>> {
        if let Some(e) = self.masters.get(uid).await {

            let id = hex::decode(id_str)
                .map_err(|e| Errors::DecodeHex(e.to_string()))?;

            let key = cha::generate_key();

            let (nonce, enc_key) = cha::encrypt(&e.master, &key)
                .map_err(|e| Errors::FailedEncKey(e.to_string()))?;

            self.db.put_key(CHA_TABLE.to_string(), uid, id.clone(), nonce, enc_key).await
                .map_err(|e| Errors::FailedPut(e.to_string()))?;

            Ok(Arc::new(KeyType::Cha(key)))
        } else {
            Err(Errors::NoMetaData)
        }
    }
}

