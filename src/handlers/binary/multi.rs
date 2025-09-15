use alloy::{ primitives::{ Bytes, FixedBytes, U256}, providers::Provider, signers::local::LocalSigner, sol };

use crate::{
     eth::node::SzProvider, handlers::{binary::{multi::Multis::MultisErrors, P2P_ID_LEN, U256_LEN}, stream::FramedStream}, keys::store::KeyStore, utils::errors::{Errors, WalletResult}
};

sol!(
    #[sol(rpc)]
    Multis,
    "assets/addrs/out/Group.sol/MaddrGroup.json"
);

pub async fn deploy(keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {

    let deployer = s.read_address()?;
    let raw_cover_charge = s.read_fix_buf(U256_LEN);
    let cover_charge = U256::from_le_slice(&raw_cover_charge);

    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &deployer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let trx = Multis::deploy_builder(pp, cover_charge, deployer)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx, signer, error_handler).await?;

    if !receipt.status() {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }

    if let Some(addr) = receipt.contract_address {
        s.mark_successful();
        s.write_address(&addr);
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

#[allow(unused)]
pub const IPV4: u8 = 1;
pub const IPV6: u8 = 2;

pub async fn new(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
)
    -> WalletResult<()> 
{
    let addr = s.read_address()?;
    let addr_to_put = s.read_address()?;
    let contract_addr = s.read_address()?;

    let raw_amount = s.read_fix_buf(U256_LEN);
    let amount = U256::from_le_slice(&raw_amount);
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &addr.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let username = new_username(&s.read_str()?);
    let protoc = s.read_fix_buf(1);
    let protocol = FixedBytes::<1>::from_slice(protoc.as_slice());

    let mut ip_length = 4; 
    if protoc[0] as u8 == IPV6 {
        ip_length = 16;
    }
    let ip_buff = s.read_fix_buf(ip_length);
    let ip = FixedBytes::<16>::from_slice(ip_buff.as_slice());

    let proxy = s.read_address()?;
    let peer_id_buff = s.read_fix_buf(P2P_ID_LEN);
    let peer_id_prefix = FixedBytes::<2>::from_slice(&peer_id_buff[..2]);
    let peer_id = FixedBytes::<32>::from_slice(&peer_id_buff[2..]);

    let multi = Multis::multi{
        verified: false,
        protocol, username, proxy, ip,
        rating: 0 as u8, rateCount: 0 as u32, 
        peerId: peer_id,
        peerIdPrefix: peer_id_prefix,
    };

    let trx = Multis::new(contract_addr, pp)
        .NewUser(addr_to_put, multi)
        .value(amount)
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

pub async fn verify(keystore: &KeyStore, 
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
)
    -> WalletResult<()> 
{
    let me = s.read_address()?;
    let contract_addr = s.read_address()?;
    let to_set_addr = s.read_address()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &me.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    // Implementation for verifying a multi-signature wallet
    let trx = Multis::new(contract_addr, pp)
        .setVerified(to_set_addr, true)
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
    let me = s.read_address()?;
    let contract_addr = s.read_address()?;
    let to_rate_addr = s.read_address()?;
    let rating = s.read_fix_buf(1)[0] as u8;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &me.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    // Implementation for rating a multi-signature wallet
    let trx = Multis::new(contract_addr, pp)
        .rate(to_rate_addr, rating)
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
    let contract_addr = s.read_address()?;
    let to_get_addr = s.read_address()?;
    let pp = node.get_provider();

    let multi = Multis::new(contract_addr, pp)
        .getMulti(to_get_addr)
        .call().await
        .map_err(|e| Errors::ContractCall(e.to_string()))?;

    let username = display_username(multi.username);
    s.mark_successful();
    s.write_buff(&[multi.verified as u8]);
    s.write_address(&multi.proxy);
    s.write_str(&username);

    s.write_buff(multi.protocol.as_slice());
    s.write_buff(multi.ip.as_slice());

    s.write_buff(&[multi.rating]);

    s.write_buff(multi.peerIdPrefix.as_slice());
    s.write_buff(&multi.peerId.as_slice());
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
