use std::{str::FromStr };

use alloy::{primitives::{ Address, FixedBytes, U256}, providers::Provider, signers::{local::LocalSigner, Signature} };
use serde::{Deserialize, Serialize};

use crate::{
    auth::store::SessionStore, crypt::{self, hashes}, eth::node::SzProvider, handlers::{ stream::FramedStream}, keys::{self, store::KeyStore}, utils::errors::{Errors, WalletResult}
};

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub name: String,
    pub pass: String,
    pub secret: String,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterResponse {
    pub mnemonic: String,
}

pub async fn register(sesh: &SessionStore, s: &mut FramedStream) 
    -> WalletResult<()> 
{
    let req = s.deserialize::<RegisterRequest>()?;

    let (uid, mnemonic) = sesh.try_register(&req.name, &req.pass, &req.secret).await?;

    s.mark_successful();
    s.serialize(&RegisterResponse {
        mnemonic: mnemonic.to_string(),
    })?;
    s.uid = uid;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct LoginRequest {
    pub name: String,
    pub pass: String,
}

#[derive(Deserialize, Serialize)]
pub struct LoginResponse {
    pub ssid: String,
}

pub async fn login( sesh: &SessionStore, keystore: &KeyStore, s: &mut FramedStream) 
    -> WalletResult<()> 
{
    let req = s.deserialize::<LoginRequest>()?;
    let (ssid, uid) = sesh.try_login(&req.name, &req.pass).await?;
    keystore.load_masters(&s.uid, &req.pass).await.unwrap();

    s.mark_successful();
    s.serialize(&LoginResponse {
        ssid: ssid.to_string(),
    })?;
    s.uid = uid;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct SignRequest {
    pub msg: Vec<u8>,
    pub addr: Address,
}

#[derive(Deserialize, Serialize)]
pub struct SignResponse {
    pub sig: Signature,
    pub hash: FixedBytes<32>,
}

pub async fn sign_sz(keystore: &KeyStore, s: &mut FramedStream, ) 
    -> WalletResult<()> 
{
    let req = s.deserialize::<SignRequest>()?;

    let key = keystore.get_sz_key(&s.uid, &req.addr.to_string()).await?;

    let (sig,hash) = hashes::socialz_sign_msg(key.as_signing()?, &req.msg)
        .map_err(|e| Errors::SignMsg(e.to_string()))?;

    s.mark_successful();
    s.serialize(&SignResponse {
        sig: sig,
        hash: hash,
    })?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct NewKeyResponse {
    pub address: Address,
}

pub async fn new_sz_key(keystore: &KeyStore, s: &mut FramedStream, ) 
    -> WalletResult<()> 
{
    let raw_sz = keystore.new_sz_key(&s.uid).await.unwrap();
    let sz_key = raw_sz.as_signing().unwrap();
    let addr = crypt::derive_address(sz_key.verifying_key());

    s.mark_successful();
    s.serialize(&NewKeyResponse {
        address: addr,
    })?;
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
    s.serialize(&NewKeyResponse {
        address: addr,
    })?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct ChaKeyResponse {
    pub key_id: String,
    pub cha_key: Vec<u8>,
}

pub async fn new_cha_key(keystore: &KeyStore, s: &mut FramedStream, )
    -> WalletResult<()> 
{
    let key_id = hex::encode(crypt::get_random(32));
    let cha_key = keystore.new_cha_key(&s.uid, &key_id).await.unwrap();
    let c_key = cha_key.as_chacha().unwrap();

    s.mark_successful();
    s.serialize(&ChaKeyResponse {
        key_id: key_id,
        cha_key: c_key.to_vec(),
    })?;
    Ok(())
}

pub async fn get_cha_key(keystore: &KeyStore, s: &mut FramedStream, )
    -> WalletResult<()> 
{
    let mut req = s.deserialize::<ChaKeyResponse>()?;

    let cha_key = keystore.get_cha_key(&s.uid, &req.key_id).await.unwrap();
    req.cha_key = cha_key.as_chacha().unwrap().to_vec();

    s.mark_successful();
    s.serialize(&req)?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct SendTrxRequest {
    pub from: Address,
    pub to: Address,
    pub amount: U256,
}

pub async fn send_trx(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
     s: &mut FramedStream,
) -> WalletResult<()> 
{
    let req = s.deserialize::<SendTrxRequest>()?;

    let raw_priv_key = keystore.get_eth_key(&s.uid, &req.from.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let receipt = node.send_trx(signer, req.to, req.amount).await
        .map_err(|e| Errors::SendTrx(e.to_string()))?;

    s.mark_successful();
    s.write_receipt(&receipt)?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct RecoverKeysRequest {
    pub mnemonic: String,
    pub password: String,
    pub count: i64,
}
#[derive(Deserialize, Serialize)]
pub struct RecoverKeysResponse {
    pub addresses: Vec<Address>,
}

pub async fn derive_sz_keys(keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream
) -> WalletResult<()> {
    let mut addresses = Vec::<Address>::new();
    let req = s.deserialize::<RecoverKeysRequest>()?;

    let seed = bip39::Mnemonic::from_str(&req.mnemonic)
        .map_err(|e| Errors::MnemonErr(e.to_string()))?
        .to_seed(req.password);

    let mut inactive_count = 0;
    let mut i = 0;
    while inactive_count < 10 || i < req.count {
        let xprv = keys::new_sz_key(i, &seed)?;
        let key = xprv.private_key();
        let addr = crypt::derive_address(key.verifying_key());
        addresses.push(addr);

        // Ask the node for transaction history
        let history = node.get_provider().get_transaction_count(addr).await
            .map_err(|e| Errors::NodeError(e.to_string()))?;

        if history > 0 || i < req.count{
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
        addresses.push(addr);
    }

    s.mark_successful();
    s.serialize(&RecoverKeysResponse {
        addresses: addresses,
    })?;
    Ok(())
}


pub async fn derive_eth_keys(keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream
) -> WalletResult<()> {
    let mut addresses = Vec::<Address>::new();

    let req = s.deserialize::<RecoverKeysRequest>()?;

    let seed = bip39::Mnemonic::from_str(&req.mnemonic)
        .map_err(|e| Errors::MnemonErr(e.to_string()))?
        .to_seed(req.password);

    let mut inactive_count = 0;
    let mut i = 0;
    while inactive_count < 10 || i < req.count {
        let xprv = keys::new_eth_key(i, &seed)?;
        let key = xprv.private_key();
        let addr = crypt::derive_address(key.verifying_key());
        addresses.push(addr);

        // Ask the node for transaction history
        let history = node.get_provider().get_transaction_count(addr).await
            .map_err(|e| Errors::NodeError(e.to_string()))?;

        if history > 0 || i < req.count{
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
    s.serialize(&RecoverKeysResponse {
        addresses: addresses,
    })?;
    Ok(())
}

