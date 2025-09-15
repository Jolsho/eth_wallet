use alloy::providers::ProviderBuilder;

use crate::{
    auth::store::SessionStore,keys::store::KeyStore, utils::db::DB
};

mod keys;
mod crypt;
mod auth;
mod utils;
mod handlers;
mod eth;
mod tests;
mod config;

pub const CONFIG_PATH: &'static str = "config.toml";

#[tokio::main]
async fn main() {
    let config = config::load_config(CONFIG_PATH)
        .expect("LOAD CONFIG FAILED");

    let db_pool = DB::new(&config).await
        .expect("DB FAILED TO OPEN");

    let sessions = SessionStore::new(db_pool.clone())
        .expect("SESSION STORE INIT FAILED");

    let keystore = KeyStore::new(db_pool)
        .expect("KEY STORE INIT FAILED");

    let provider = eth::node::SzProvider::new(
        ProviderBuilder::new()
            .connect(&config.eth.url).await
            .expect("SZ PROVIDER INIT FAILED")
    );

    let _handle = handlers::start_listener(sessions,keystore, provider, &config).await.await;
}
