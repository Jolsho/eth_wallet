use crate::config::{Config, DatabaseConfig, EthConfig, SocketConfig};

pub fn load_test_config(test_name: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let test_config = Config {
        db: def_db(test_name),
        unix: def_socket(test_name),
        eth: def_eth(),
    };
    Ok(test_config)

}

fn def_db(test_name: &str) -> DatabaseConfig {
    DatabaseConfig {
        path: def_db_path(test_name),
        schema_path: def_db_schema_path(),
        pool_size: def_db_pool_size(),
    }
}

fn def_socket(test_name: &str) -> SocketConfig {
    SocketConfig {
        path: def_unix_path(test_name),
    }
}
fn def_eth() -> EthConfig {
    EthConfig {
        url: def_eth_rpc_url(),
    }
}

pub fn def_db_path(test_name: &str) -> String {
    format!("assets/test_data_{}.db", test_name)
}
pub fn def_db_schema_path() -> String {
    "assets/schema.sql".into()
}
fn def_db_pool_size() -> u32 {
    10
}

pub fn def_unix_path(test_name: &str) -> String {
    format!("assets/test_wallet_{}.sock", test_name)
}

fn def_eth_rpc_url() -> String {
    "http://localhost:8545".into()
}

