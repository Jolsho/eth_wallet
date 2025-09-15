use std::cmp::Ordering;
use std::{ sync::Arc, time::Duration };
use bip39::Mnemonic;
use chacha20poly1305::Key;
use deadpool_sqlite::rusqlite;
use k256::{sha2::{Sha256,Digest}};

use crate::utils::errors::{Errors, WalletResult};
use crate::{ crypt, keys, utils };
use crate::{ auth::db::UserDB};
use crate::auth::cache::UserCache;

pub struct SessionStore {
    pub sessions: UserCache,
    pub db: UserDB,
}

pub const SSID_LEN: usize = 20;

impl SessionStore { 
    pub fn new(db: utils::db::DB) -> Result<Arc<Self>, rusqlite::Error> {
        Ok(Arc::new(Self { 
            db: db,
            sessions: UserCache::new(Duration::new(10, 0), 100),
        }))
    }

    /// returns session_id, uid
    pub async fn try_login(&self, uname:&str, pword:&str) -> WalletResult<(String,String)> {
        let (uid, target, salt) = self.db.get_user(uname).await?;
        let mut p_hasher = Sha256::new();
        p_hasher.update(pword);
        p_hasher.update(&salt);
        let hashword = p_hasher.finalize();

        if hashword.as_slice().cmp(&target) != Ordering::Equal {
            return Err(Errors::InvalidCredentials)
        }

        if !self.sessions.exists(&uid).await {
            Ok((self.sessions.create(&uid).await, uid.to_string()))
        } else {
            Err(Errors::NeedSessionId)
        }
    }

// TODO -- rotating secret for registration
// like a rolling code everytime one is used the next one is generated
// this means you need an admin status for users...
// those would be the ones who could retrieve that key
// they should also be able to remove other users
    /// returns session_id, uid, mnemonic
    pub async fn try_register(&self, uname: &str, pword:&str, _secret: &str) 
        -> WalletResult<(String, String)>
    {
        let entropy = crypt::get_random(32);
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| Errors::MnemonErr(e.to_string()))?.to_string();

        let salt = crypt::get_random(16);
        let mut pword_hasher = Sha256::new();
        pword_hasher.update(pword);
        pword_hasher.update(&salt);
        let hashword = pword_hasher.finalize().to_vec();

        let mut uid_hasher = Sha256::new();
        uid_hasher.update(uname);
        uid_hasher.update(pword);
        uid_hasher.update(&salt);
        let uid = hex::encode(&uid_hasher.finalize()[..8]);

        let m_salt = crypt::get_random(16);
        let raw_master = keys::derive_argon_key(pword, &m_salt);
        let master = Key::from_slice(&raw_master);

        let (mnem_nonce, enc_mnem) = crypt::cha::encrypt(master, mnemonic.as_bytes())
            .map_err(|e| Errors::MnemonErr(e.to_string()))?;

        self.db.insert_user(
            &uid, uname, hashword, salt, m_salt, enc_mnem.clone(), mnem_nonce
        ).await?;
        Ok((uid, mnemonic))
    }

    pub async fn try_authorize(&self, uid: &str, ssid: &str) -> WalletResult<()> {
        if let Some(e) = self.sessions.get(ssid).await {
            if e.data == uid {
                Ok(())
            } else {
                Err(Errors::Unauthorized)
            }
        } else {
            Err(Errors::Unauthorized)
        }
    }
}
