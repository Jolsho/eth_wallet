use chacha20poly1305::{Key};
use tokio::sync::RwLock;

use crate::keys::{db, KeyType};
use crate::utils::cache::{Cache, Cacheable};

use std::{sync::{Arc}, };

pub struct KeyEntry {
    pub key: Arc<KeyType>,
}

impl Cacheable for KeyEntry {
    type Item = KeyType;

    fn new(key: KeyType) -> Self {
        Self { key: Arc::new(key) }
    }
}

pub type KeyCache = Cache<KeyEntry>;
pub type MasterCache = Cache<MasterEntry>;

pub struct MasterEntry {
    pub idxs: RwLock<Idxs>,
    pub master: Key,
    pub seed: [u8;64],
}

pub struct Idxs {
    pub socialz: i64,
    pub ether: i64,
}

pub type MasterVector = (Idxs, Key, [u8;64]);

impl Cacheable for MasterEntry {
    type Item = MasterVector;

    fn new(m: MasterVector) -> Self {
        Self {
            idxs: RwLock::new(m.0),
            master:m.1, seed:m.2, 
        }
    }

}


impl MasterCache {
    pub async fn get_idx_seed_master(&self, uid: &str, table: &str) -> Option<(i64, Arc<MasterEntry>)> {
        if let Some(m) = self.get(uid).await {
            let mut d = m.idxs.write().await;
            let idx = match table {
                db::SZ_TABLE => {
                    d.socialz += 1;
                    d.socialz
                },
                db::ETH_TABLE => {
                    d.ether += 1;
                    d.ether
                },
                _  => 0,
            };
            Some((idx, m.clone()))
        } else {
            None
        }
    }
}


