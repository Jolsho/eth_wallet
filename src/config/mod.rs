use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use serde::Deserialize;
use serde::Serialize; // Needed to write default config

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "def_db")]
    pub db: DatabaseConfig,
    #[serde(default = "def_socket")]
    pub unix: SocketConfig,

    #[serde(default = "def_eth")]
    pub eth: EthConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DatabaseConfig {

    #[serde(default = "def_db_path")]
    pub path: String,

    #[serde(default = "def_db_schema_path")]
    pub schema_path: String,

    #[serde(default = "def_db_pool_size")]
    pub pool_size: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SocketConfig {
    #[serde(default = "def_unix_path")]
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EthConfig {
    #[serde(default = "def_eth_rpc_url")]
    pub url: String,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    if !Path::new(path).exists() {
        let default_config = Config {
            db: def_db(),
            unix: def_socket(),
            eth: def_eth(),
        };
        let toml_string = toml::to_string_pretty(&default_config)?;
        let mut file = File::create(path)?;
        file.write_all(toml_string.as_bytes())?;
    }

    let contents = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

fn def_db() -> DatabaseConfig {
    DatabaseConfig {
        path: def_db_path(),
        schema_path: def_db_schema_path(),
        pool_size: def_db_pool_size(),
    }
}

fn def_socket() -> SocketConfig {
    SocketConfig {
        path: def_unix_path(),
    }
}

fn def_db_path() -> String {
    "assets/data.db".into()
}
fn def_db_schema_path() -> String {
    "assets/schema.sql".into()
}
fn def_db_pool_size() -> u32 {
    10
}
fn def_unix_path() -> String {
    "assets/wallet.sock".into()
}

fn def_eth_rpc_url() -> String {
    "http://localhost:8545".into()
}

pub fn def_eth() -> EthConfig {
    EthConfig {
        url: def_eth_rpc_url(),
    }
}
