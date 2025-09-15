#![cfg(test)]
pub mod config;
pub mod binary;
pub mod json;

use std::sync::Arc;
use std::{path::PathBuf, str::FromStr};
use std::fs;

use alloy::providers::{Provider, ProviderBuilder};
use alloy_node_bindings::{Anvil, AnvilInstance};
use tokio::net::UnixStream;

use crate::auth::store::SessionStore;
use crate::eth::node::SzProvider;
use crate::handlers::start_listener;
use crate::handlers::stream::FramedStream;
use crate::keys::store::KeyStore;
use crate::utils::db::DB;

pub struct TestFileGuard {
    pub path: PathBuf,
}

impl TestFileGuard { pub fn new(raw_path: &str) -> Self {
        let path = PathBuf::from_str(raw_path).unwrap();
        Self { path }
    }
}

impl Drop for TestFileGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_file(&self.path)
                .expect("Failed to remove test DB file");
        }
    }
}

#[allow(unused)]
pub struct TestStuff<P: Provider + Clone> {
    pub dbguard: TestFileGuard,
    pub sockguard: TestFileGuard,
    pub db_pool: DB,
    pub sessions: Arc<SessionStore>,
    pub keystore: Arc<KeyStore>,
    pub provider: SzProvider<P>,
    pub stream: FramedStream,
    pub node: AnvilInstance,
}

pub async fn start_test(test_name: &str) -> TestStuff<impl Provider + Clone> {
    let _dbguard = TestFileGuard::new(&config::def_db_path(test_name));
    let sockguard = TestFileGuard::new(&config::def_unix_path(test_name));

    let config = config::load_test_config(test_name)
        .expect("CONFIG LOAD FAILED");

    let db_pool = DB::new(&config).await.unwrap();
    let sessions = SessionStore::new(db_pool.clone()).unwrap();
    let keystore = KeyStore::new(db_pool.clone()).unwrap();

    let anvil = Anvil::new().try_spawn().expect("Failed to spawn Anvil");
    let rpc_url = anvil.endpoint();
    let raw_provider = ProviderBuilder::new()
        .connect(&rpc_url)
        .await.unwrap();

    let provider = SzProvider::new(raw_provider);
    let passable_provider = provider.clone();

    let _ = start_listener(sessions.clone(),keystore.clone(), passable_provider.clone(), &config).await;
    let raw_stream = UnixStream::connect(&sockguard.path).await.expect("Failed to connect.");
    let stream = FramedStream::new(raw_stream);

    TestStuff {
        dbguard: _dbguard, sockguard, db_pool, 
        sessions, keystore, provider, stream,
        node: anvil,
    }
}
