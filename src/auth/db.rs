use deadpool_sqlite::rusqlite;
use rusqlite::{params};

use crate::utils::errors::{Errors, WalletResult};
use crate::utils::{self};

pub type UserDB = utils::db::DB;

impl UserDB {
    pub async fn get_user<'a>(&self, uname: &'a str) 
    -> WalletResult<(String,[u8;32],[u8;16])> {
        let conn = self.pool.get().await.unwrap();
        let name = uname.to_string();
        let res = conn.interact::<_, WalletResult<(String, [u8; 32], [u8; 16])>>(move |conn| {
            let cmd = "SELECT uid, hashword, salt FROM users WHERE username = ?1;";

            let res : (String, [u8;32], [u8;16]) = conn.query_row(cmd, 
                    params![name], 
                    |row| {
                        let uid = row.get(0)?;
                        let hashword = row.get(1)?;
                        let salt = row.get(2)?;
                        Ok((uid, hashword, salt))
                    }
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Errors::InvalidCredentials,
                    _ => {
                        Errors::Other(e.to_string())
                    },
                })?;

            Ok(res)
        }).await.map_err(|e| Errors::Interact(e.to_string()))?.unwrap();
        Ok(res)
    }
    pub async fn insert_user(&self,
        uid: &str, uname: &str, hashword: Vec<u8>, 
        salt: Vec<u8>, m_salt: Vec<u8>,
        mnemonic: Vec<u8>, mn_nonce: Vec<u8>,
    ) -> WalletResult<()> {
        let conn = self.pool.get().await.unwrap();
        let name = uname.to_string();
        let uuid = uid.to_string();

        let res = conn.interact::<_, WalletResult<()>>(move |conn| {
            let cmd = "
                INSERT INTO users (uid, username, hashword, salt, m_salt, mnemonic, mn_nonce) 
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);
            ";
            let _ = conn.execute(cmd, params![uuid, name, hashword, salt, m_salt, mnemonic, mn_nonce])
                .map_err(|e| match e {
                    rusqlite::Error::SqliteFailure(err, Some(_)) => {
                        if err.code ==rusqlite::ErrorCode::ConstraintViolation {
                             Errors::UsernameExists
                        } else {
                            Errors::FailedPut(err.to_string())
                        }
                    },
                    _ => Errors::FailedPut(e.to_string()),
                })?;
            Ok(())
        }).await.map_err(|e| Errors::Interact(e.to_string()))?.unwrap();
        Ok(res)
    }
}
