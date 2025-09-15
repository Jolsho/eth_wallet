use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::Provider;
use alloy::signers::local::LocalSigner;
use alloy::sol;
use serde::{Deserialize, Serialize};

use crate::eth::node::SzProvider;
use crate::handlers::binary::auction::Auction::AuctionErrors;
use crate::handlers::stream::FramedStream;
use crate::keys::store::KeyStore;
use crate::utils::errors::{Errors, WalletResult};

sol!(
    #[sol(rpc)]
    Auction,
    "assets/addrs/out/Auction.sol/SimpleAuction.json"
);

#[derive(Deserialize, Serialize)]
pub struct DeployAuction {
    pub deployer: Address,
    pub beneficiary: Address,
    pub end_time: U256,
}

#[derive(Deserialize, Serialize)]
pub struct ContractCall {
    pub address: Address,
    pub contract_addr: Address,
}

#[derive(Deserialize, Serialize)]
pub struct DeployContractResponse {
    pub contract_address: Address,
    pub receipt: Option<TrxReceipt>,
}

#[derive(Deserialize, Serialize)]
pub struct AuctionBid {
    pub bidder: Address,
    pub contract_addr: Address,
    pub amount: U256,
}

#[derive(Deserialize, Serialize)]
pub struct AuctionInfo {
    pub beneficiary: Address,
    pub contract_addr: Address,
    pub end_time: U256,
}

#[derive(Deserialize, Serialize)]
pub struct TrxReceipt {
    pub transaction_hash: FixedBytes<32>,
    pub block_hash: FixedBytes<32>,
    pub status: bool,
    pub gas_used: u64,
    pub gas_price: u128,
    pub block_number: u64,
}

pub async fn deploy(
    keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {

    let m = s.deserialize::<DeployAuction>()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &m.deployer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let trx_req = Auction::deploy_builder(pp, m.end_time, m.beneficiary)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx_req, signer, error_handler).await?;

    if !receipt.status() {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }

    if let Some(addr) = receipt.contract_address {
        let response = DeployContractResponse {
            contract_address: addr,
            receipt: Some(TrxReceipt {
                transaction_hash: receipt.transaction_hash,
                block_hash: receipt.block_hash.unwrap_or_default(),
                gas_price: receipt.effective_gas_price,
                gas_used: receipt.gas_used,
                block_number: receipt.block_number.unwrap_or_default(),
                status: true,
            }),
        };
        s.mark_successful();
        s.serialize(&response)?;
    } else {
        return Err(Errors::SendTrx("No contract address returned".to_string()));
    }
    Ok(())
}


pub async fn bid(
    keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {
    let m = s.deserialize::<AuctionBid>()?;

    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &m.bidder.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let bid_trx = Auction::new(m.contract_addr, pp)
        .bid().value(m.amount)
        .into_transaction_request();

    let receipt = node.send_contract_trx(bid_trx, signer, error_handler).await?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }
    Ok(())
}

pub async fn withdraw(
    keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {
    let req = s.deserialize::<ContractCall>()?;

    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &req.address.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let withdraw_trx = Auction::new(req.contract_addr, pp)
        .withdraw().from(req.address)
        .into_transaction_request();

    let receipt = node.send_contract_trx(withdraw_trx, signer, error_handler).await?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }
    Ok(())
}

pub async fn end(
    keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {
    let req = s.deserialize::<ContractCall>()?;

    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &req.address.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let end_trx = Auction::new(req.contract_addr, pp)
        .auctionEnd().into_transaction_request();

    let receipt = node.send_contract_trx(end_trx, signer, error_handler).await?;

    if receipt.status() {
        s.mark_successful();
        s.write_receipt(&receipt)?;
    } else {
        return Err(Errors::SendTrx("Transaction failed".to_string()));
    }
    Ok(())
}


pub async fn get_auction(
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {
    let req = s.deserialize::<ContractCall>()?;

    let pp = node.get_provider();

    let auction = Auction::new(req.contract_addr, pp);
    
    let end_time = auction.auctionEndTime().call().await
        .map_err(|e| Errors::ContractCall(e.to_string()))?;
    let beneficiary = auction.beneficiary().call().await
        .map_err(|e| Errors::ContractCall(e.to_string()))?;

    let auction_info = AuctionInfo {
        beneficiary, end_time,
        contract_addr: req.contract_addr,
    };
    s.mark_successful();
    s.serialize(&auction_info)
}

fn error_handler(error: Option<AuctionErrors>, _data: Option<Bytes>) -> Errors {
    match error {
        Some(AuctionErrors::BidNotHighEnough(_)) => {
            Errors::ContractCall("Bid Not High Enough".to_string())
        },
        Some(AuctionErrors::AuctionNotYetEnded(_)) => {
            Errors::ContractCall("Auction Not Yet Ended".to_string())
        },
        Some(AuctionErrors::AuctionAlreadyEnded(_)) => {
            Errors::ContractCall("Auctin Already Ended".to_string())
        },
        Some(AuctionErrors::AuctionEndAlreadyCalled(_)) => {
            Errors::ContractCall("Auctin End Already Called".to_string())
        },
        _ => Errors::ContractCall(format!("Unknown Auction Error")),
    }
}
