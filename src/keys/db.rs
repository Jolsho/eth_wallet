use deadpool_sqlite::rusqlite::{params};

use crate::{
    crypt, utils::{self, errors::{Errors, WalletResult}}
};


pub const ETH_TABLE: &'static str = "eth_keys";
pub const SZ_TABLE: &'static str = "sz_keys";
pub const CHA_TABLE: &'static str = "sym_keys";

pub type MastersReturn = (Vec<u8>,Vec<u8>,Vec<u8>,i64,i64);

pub type KeyDB = utils::db::DB;
impl KeyDB {

    pub async fn get_key(&self, table: String, uid: &str, id: &str) ->
        Result<(Vec<u8>,Vec<u8>), Errors>
    {
        let conn = self.pool.get().await.unwrap();
        let uuid = uid.to_string();
        let iid = id.to_string();
        let res = conn.interact::<_, WalletResult<(Vec<u8>,Vec<u8>)>>(move |conn| {
            is_valid_table(&table)?;
            let other_id = derive_other_id(&table)?;
            let id_bytes = id_bytes(&table, &iid)?;
            let cmd = format!("SELECT prk, nonce FROM {} WHERE uid = ?1 AND {} = ?2", table, other_id);
            let (prk, nonce): (Vec<u8>,Vec<u8>) = conn.query_row(&cmd, params![uuid, id_bytes], 
                |row| {
                    let prk = row.get(0)?;
                    let nonce = row.get(1)?;
                    Ok((prk, nonce))
                })
                .map_err(|e|Errors::QueryErr(e.to_string()))?;

            Ok((prk,nonce))
        }).await.map_err(|e| Errors::Interact(e.to_string()))?.unwrap();
        Ok(res)
    }

    pub async fn put_key(&self, table:String, uid:&str, 
        other_id: Vec<u8>, nonce:Vec<u8>, enc_key:Vec<u8>,
    )
        -> WalletResult<()>
    {
        let conn = self.pool.get().await.unwrap();
        let uuid = uid.to_string();
        let res = conn.interact::<_, WalletResult<()>>(move |conn| {
            is_valid_table(&table)?;
            let other_name = derive_other_id(&table)?;
            let cmd = format!("INSERT INTO {} (uid,{},nonce,prk) VALUES (?1,?2,?3,?4);", table, other_name);
            conn.execute(&cmd, params![uuid, other_id, &nonce, &enc_key])
                .map_err(|e|Errors::ExecErr(e.to_string()))?;
            Ok(())
        }).await.map_err(|e| Errors::Interact(e.to_string()))?.unwrap();
        Ok(res)
    }

    pub async fn get_masters(&self, uid:&str) -> WalletResult<MastersReturn> {
        let conn = self.pool.get().await.unwrap();
        let uuid = uid.to_string();
        let res = conn.interact::<_, WalletResult<MastersReturn>>(move |conn| {
            let cmd ="SELECT m_salt, mn_nonce, mnemonic, sz_count, eth_count FROM users WHERE uid = ?1";
            let res: MastersReturn = 
                conn.query_row(&cmd, params![uuid], 
                    |row| {
                        let m_salt = row.get(0)?;
                        let mn_nonce = row.get(1)?;
                        let mnem = row.get(2)?;
                        let sz_count = row.get(3)?;
                        let eth_count = row.get(4)?;
                        Ok((m_salt,mnem,mn_nonce,sz_count,eth_count))
                    })
                    .map_err(|e|Errors::QueryErr(e.to_string()))?;

            Ok(res)
        }).await.map_err(|e| Errors::Interact(e.to_string()))?.unwrap();
        Ok(res)
    }

}
fn derive_other_id(table:&str) -> WalletResult<String>  {
    match table {
        SZ_TABLE | ETH_TABLE => Ok("addr".to_string()),
        CHA_TABLE => Ok("id".to_string()),
        _ => return Err(Errors::BadTable(table.to_string())),
    }
}
fn id_bytes(table:&str, id: &str) -> WalletResult<Vec<u8>>  {
    match table {
        SZ_TABLE | ETH_TABLE => 
            Ok(crypt::eip55::from_eip55(id)
                .map_err(|e|Errors::Other(e.to_string()))?.to_vec()
            ),

        CHA_TABLE => Ok(hex::decode(id)
                .map_err(|e|Errors::Other(e.to_string()))?.to_vec()
            ),
        _ => return Err(Errors::BadTable(table.to_string())),
    }
}

fn is_valid_table(table: &str) -> WalletResult<()> {
    match table {
        SZ_TABLE | ETH_TABLE | CHA_TABLE => table,
        _ => return Err(Errors::BadTable(table.to_string())),
    };
    Ok(())
}
