use std::path::PathBuf;

use crate::config::Config;

#[derive(Clone)]
pub struct DB {
    pub pool: deadpool_sqlite::Pool
}

impl DB {
    pub async fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {

        let mut pool_builder = deadpool_sqlite::PoolConfig::new(config.db.pool_size as usize);
        pool_builder.timeouts.wait = Some(std::time::Duration::from_secs(5));
        pool_builder.timeouts.create = Some(std::time::Duration::from_secs(5));
        pool_builder.timeouts.recycle = None;

        let cfg = deadpool_sqlite::Config {
            path: PathBuf::from(&config.db.path),
            pool: Some(pool_builder),
        };

        let pool = cfg.create_pool(deadpool_sqlite::Runtime::Tokio1).unwrap();

        let tmp_con = pool.get().await.unwrap();

        // Load the schema from file
        let schema = std::fs::read_to_string(&config.db.schema_path)
            .expect("Failed to read schema.sql");
        
        // Execute the entire schema
        tmp_con.interact(move |conn| {
            conn.execute_batch(&schema)
        }).await??;

        Ok(Self { pool })
    }
}
