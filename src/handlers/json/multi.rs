use alloy::{ primitives::{ Address, Bytes, FixedBytes, U256}, providers::Provider, signers::local::LocalSigner, sol };
use serde::{Deserialize, Serialize};

use crate::{
     eth::node::SzProvider, handlers::{binary::multi::Multis::MultisErrors, json::auction::{TrxReceipt, DeployContractResponse}, stream::FramedStream}, keys::store::KeyStore, utils::errors::{Errors, WalletResult}
};

sol!(
    #[sol(rpc)]
    Multis,
    "assets/addrs/out/Group.sol/MaddrGroup.json"
);

#[derive(Deserialize, Serialize)]
pub struct DeployMulti {
    pub deployer: alloy::primitives::Address,
    pub cover_charge: U256,
}

pub async fn deploy(keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {

    let m = s.deserialize::<DeployMulti>()?;

    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &m.deployer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let trx = Multis::deploy_builder(pp, m.cover_charge, m.deployer)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx, signer, error_handler).await?;

    if !receipt.status() {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }

    if let Some(addr) = receipt.contract_address {
        s.mark_successful();
        s.serialize(&DeployContractResponse {
            contract_address: addr,
            receipt: Some(TrxReceipt {
                gas_used: receipt.gas_used,
                gas_price: receipt.effective_gas_price,
                block_number: receipt.block_number.unwrap_or_default(),
                transaction_hash: receipt.transaction_hash,
                block_hash: receipt.block_hash.unwrap_or_default(),
                status: true,
            }),
        })?;
    } else {
        return Err(Errors::SendTrx("No contract address returned".to_string()));
    }
    Ok(())
}

fn new_username(name: &str) -> FixedBytes<8> {
    let mut buf = [b'\0'; 8]; // start filled with filler
    let bytes = name.as_bytes();
    let len = bytes.len().min(8); // avoid overflow
    buf[..len].copy_from_slice(&bytes[..len]);

    alloy::primitives::FixedBytes::new(buf)
}

fn display_username(buff: FixedBytes<8>) -> String {
    let end = buff.iter()
        .position(|&b| b == b'\0') // find first null
        .unwrap_or(buff.len());
    String::from_utf8_lossy(&buff[..end]).into_owned()
}

#[derive(Deserialize, Serialize)]
pub struct NewMulti {
    pub addr: Address,
    pub addr_to_put: Address,
    pub contract_addr: Address,
    pub amount: U256,
    pub username: String,
    pub protocol: FixedBytes<1>,
    pub ip: FixedBytes<16>,
    pub proxy: Address,
    pub peer_id: FixedBytes<34>,
    pub rating: u8,
}

pub async fn new(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
)
    -> WalletResult<()> 
{
    let r = s.deserialize::<NewMulti>()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &r.addr.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let peer_id_prefix = FixedBytes::<2>::from_slice(&r.peer_id[..2]);
    let peer_id = FixedBytes::<32>::from_slice(&r.peer_id[2..]);

    let multi = Multis::multi{
        verified: false,
        protocol: r.protocol, 
        username: new_username(&r.username), 
        proxy: r.proxy,
        ip: r.ip,
        rating: 0 as u8, rateCount: 0 as u32, 
        peerId: peer_id,
        peerIdPrefix: peer_id_prefix,
    };

    let trx = Multis::new(r.contract_addr, pp)
        .NewUser(r.addr_to_put, multi)
        .value(r.amount)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx, signer, error_handler).await?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
pub struct AddressTriple {
    pub signer: Address,
    pub addr: Address,
    pub contract_addr: Address,
    pub number: u8,
}

pub async fn verify(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
)
    -> WalletResult<()> 
{
    let r = s.deserialize::<AddressTriple>()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &r.signer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    // Implementation for verifying a multi-signature wallet
    let trx = Multis::new(r.contract_addr, pp)
        .setVerified(r.addr, true)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx, signer, error_handler).await?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }
    Ok(())
}

pub async fn rate(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
)
    -> WalletResult<()> 
{
    let req = s.deserialize::<AddressTriple>()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &req.signer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    // Implementation for rating a multi-signature wallet
    let trx = Multis::new(req.contract_addr, pp)
        .rate(req.addr, req.number)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx, signer, error_handler).await?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }
    Ok(())
}

pub async fn get_multi(
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,) 
    -> WalletResult<()> 
{
    let r = s.deserialize::<AddressTriple>()?;
    let pp = node.get_provider();

    let multi = Multis::new(r.contract_addr, pp)
        .getMulti(r.addr)
        .call().await
        .map_err(|e| Errors::ContractCall(e.to_string()))?;

    let username = display_username(multi.username);
    let mut peer_id = FixedBytes::<34>::new([0; 34]);
    peer_id[..2].copy_from_slice(multi.peerIdPrefix.as_slice());
    peer_id[2..].copy_from_slice(multi.peerId.as_slice());

    s.mark_successful();
    s.serialize(&NewMulti {
        addr: r.addr,
        addr_to_put: Address::ZERO,
        contract_addr: r.contract_addr,
        amount: U256::ZERO,
        username: username.clone(),
        protocol: multi.protocol,
        ip: multi.ip,
        proxy: multi.proxy,
        peer_id: peer_id,
        rating: multi.rating,
    })?;
    Ok(())
}

fn error_handler(error: Option<MultisErrors>, _data: Option<Bytes>) -> Errors {
    match error {
        Some(MultisErrors::Unauthorized(_)) => {
            Errors::ContractCall("Unauthorized".to_string())
        },
        Some(MultisErrors::InvalidAddress(_)) => {
            Errors::ContractCall("Invalid Address".to_string())
        },
        Some(MultisErrors::InsufficientBalance(_)) => {
            Errors::ContractCall("Insuffecient Balance".to_string())
        },
        Some(MultisErrors::MustBeFull(_)) => {
            Errors::ContractCall("Must Be Full".to_string())
        },
        Some(MultisErrors::NotCovered(_)) => {
            Errors::ContractCall("Not Covered".to_string())
        },
        Some(MultisErrors::MustBeEmpty(_)) => {
            Errors::ContractCall("Must Be Empty".to_string())
        },
        Some(MultisErrors::BadRating(_)) => {
            Errors::ContractCall("Must Be Empty".to_string())
        },
        Some(MultisErrors::NotVerified(_)) => {
            Errors::ContractCall("Must Be Empty".to_string())
        },
        _ => Errors::ContractCall(format!("Unknown Multi Error")),
    }
}
