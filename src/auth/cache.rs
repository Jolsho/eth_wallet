use rand::{rngs::OsRng, TryRngCore};

use crate::{auth::store::SSID_LEN, utils::{self}};

pub struct UserEntry {
    pub data: String,
}

impl utils::cache::Cacheable for UserEntry {
    type Item = String;
    fn new(data: String) -> Self {
        Self { data }
    }
}

pub type UserCache = utils::cache::Cache<UserEntry>;

impl UserCache {
    /// returns session_id
    pub async fn create(&self, uid: &str) -> String {
        let mut buf = [0u8; SSID_LEN];
        OsRng.try_fill_bytes(&mut buf).unwrap();
        let session_id = hex::encode(buf)[..SSID_LEN].to_string();
        self.put(&session_id, uid.to_string()).await;
        session_id
    }
}
