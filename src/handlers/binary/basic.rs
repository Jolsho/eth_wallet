use std::{str::FromStr };

use alloy::{primitives::{ Address, U256}, providers::Provider, signers::local::LocalSigner };

use crate::{
    auth::store::SessionStore, crypt::{self, hashes}, eth::node::SzProvider, handlers::{ binary::U256_LEN, stream::FramedStream}, keys::{self, store::KeyStore}, utils::errors::{Errors, WalletResult}
};


pub async fn register(sesh: &SessionStore, s: &mut FramedStream) 
    -> WalletResult<()> 
{
    let name = s.read_str()?;
    let pass = s.read_str()?;
    let secret = s.read_str()?;
    let (uid, mnemonic) = sesh.try_register(&name, &pass, &secret).await?;

    s.mark_successful();
    s.write_str(&mnemonic);
    s.uid = uid;
    Ok(())
}

pub async fn login( sesh: &SessionStore, keystore: &KeyStore, s: &mut FramedStream) 
    -> WalletResult<()> 
{
    let name = s.read_str()?;
    let pass = s.read_str()?;
    let (ssid, uid) = sesh.try_login(&name, &pass).await?;
    keystore.load_masters(&s.uid, &pass).await.unwrap();

    s.mark_successful();
    s.write_str(&ssid);
    s.uid = uid;
    Ok(())
}

pub async fn sign_sz(keystore: &KeyStore, s: &mut FramedStream, ) 
    -> WalletResult<()> 
{
    let msg = s.read_var_buf()?;
    let addr = s.read_address()?;

    let key = keystore.get_sz_key(&s.uid, &addr.to_string()).await?;

    let (sig,hash) = hashes::socialz_sign_msg(key.as_signing()?, &msg)
        .map_err(|e| Errors::SignMsg(e.to_string()))?;

    s.mark_successful();
    s.write_buff(&sig.as_bytes());
    s.write_buff(hash.as_slice());
    Ok(())
}

pub async fn new_sz_key(keystore: &KeyStore, s: &mut FramedStream, ) 
    -> WalletResult<()> 
{
    let raw_sz = keystore.new_sz_key(&s.uid).await.unwrap();
    let sz_key = raw_sz.as_signing().unwrap();
    let addr = crypt::derive_address(sz_key.verifying_key());

    s.mark_successful();
    s.write_address(&addr);
    Ok(())
}

pub async fn new_eth_key(keystore: &KeyStore, s: &mut FramedStream, )
    -> WalletResult<()> 
{
    let raw_eth = keystore.new_eth_key(&s.uid).await.unwrap();
    let eth_key = raw_eth.as_signing().unwrap();
    let v_eth = eth_key.verifying_key();
    let addr = crypt::derive_address(v_eth);

    s.mark_successful();
    s.write_address(&addr);
    Ok(())
}

pub async fn new_cha_key(keystore: &KeyStore, s: &mut FramedStream, )
    -> WalletResult<()> 
{
    let key_id = hex::encode(crypt::get_random(32));
    let cha_key = keystore.new_cha_key(&s.uid, &key_id).await.unwrap();
    let c_key = cha_key.as_chacha().unwrap();

    s.mark_successful();
    s.write_str(&key_id);
    s.write_buff_and_len(c_key);
    Ok(())
}

pub async fn get_cha_key(keystore: &KeyStore, s: &mut FramedStream, )
    -> WalletResult<()> 
{
    let key_id = s.read_str()?;
    let cha_key = keystore.get_cha_key(&s.uid, &key_id).await.unwrap();
    let c_key = cha_key.as_chacha().unwrap();

    s.mark_successful();
    s.write_buff_and_len(c_key);
    Ok(())
}

pub async fn send_trx(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
     s: &mut FramedStream,
) -> WalletResult<()> 
{
    let from_addr = s.read_address()?;
    let to_addr = s.read_address()?;
    
    let raw_amount = s.read_fix_buf(U256_LEN);
    let amount = U256::from_le_slice(&raw_amount);

    let raw_priv_key = keystore.get_eth_key(&s.uid, &from_addr.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let receipt = node.send_trx(signer, to_addr, amount).await
        .map_err(|e| Errors::SendTrx(e.to_string()))?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }

    s.mark_successful();
    Ok(())
}

pub async fn derive_sz_keys(keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream
) -> WalletResult<()> {

    let mnemonic = s.read_str()?;
    let password = s.read_str()?;
    let seed = bip39::Mnemonic::from_str(&mnemonic)
        .map_err(|e| Errors::MnemonErr(e.to_string()))?
        .to_seed(password);

    let mut inactive_count = 0;
    let mut i = 0;
    while inactive_count < 10 {
        let xprv = keys::new_sz_key(i, &seed)?;
        let key = xprv.private_key();
        let addr = crypt::derive_address(key.verifying_key());

        // Ask the node for transaction history
        let history = node.get_provider().get_transaction_count(addr).await
            .map_err(|e| Errors::NodeError(e.to_string()))?;

        if history > 0 {
            keystore.put_sz_key(&s.uid, addr, key.clone()).await?;
            inactive_count = 0; // reset counter if we found a key with balance
        } else {
            inactive_count += 1;
        }
        
        i += 1;
    }

    if i == inactive_count {
        let xprv = keys::new_eth_key(0, &seed)?;
        let key = xprv.private_key();
        let addr = crypt::derive_address(key.verifying_key());
        keystore.put_sz_key(&s.uid, addr, key.clone()).await?;
    }

    s.mark_successful();
    Ok(())
}

pub async fn derive_eth_keys(keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream
) -> WalletResult<()> {
    let mut addresses = Vec::<Address>::new();
    let mnemonic = s.read_str()?;
    let password = s.read_str()?;
    let count = s.read_fix_buf(1)[0] as i64;

    let seed = bip39::Mnemonic::from_str(&mnemonic)
        .map_err(|e| Errors::MnemonErr(e.to_string()))?
        .to_seed(password);

    let mut inactive_count = 0;
    let mut i = 0;
    while inactive_count < 10 || i < count {
        let xprv = keys::new_eth_key(i, &seed)?;
        let key = xprv.private_key();
        let addr = crypt::derive_address(key.verifying_key());
        addresses.push(addr);

        // Ask the node for transaction history
        let history = node.get_provider().get_transaction_count(addr).await
            .map_err(|e| Errors::NodeError(e.to_string()))?;

        if history > 0 || i < count{
            keystore.put_eth_key(&s.uid, addr, key.clone()).await?;
            inactive_count = 0; // reset counter if we found a key with balance
        } else {
            inactive_count += 1;
        }
        
        i += 1;
    }

    if i == inactive_count {
        let xprv = keys::new_eth_key(0, &seed)?;
        let key = xprv.private_key();
        let addr = crypt::derive_address(key.verifying_key());
        keystore.put_eth_key(&s.uid, addr, key.clone()).await?;
        addresses.push(addr);
    }

    s.mark_successful();
    s.write_address_array(&addresses);
    Ok(())
}

