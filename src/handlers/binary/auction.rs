
use alloy::primitives::{Bytes, U256};
use alloy::providers::Provider;
use alloy::signers::local::LocalSigner;
use alloy::sol;

use crate::eth::node::SzProvider;
use crate::handlers::binary::auction::Auction::AuctionErrors;
use crate::handlers::binary::U256_LEN;
use crate::handlers::stream::FramedStream;
use crate::keys::store::KeyStore;
use crate::utils::errors::{Errors, WalletResult};

sol!(
    #[sol(rpc)]
    Auction,
    "assets/addrs/out/Auction.sol/SimpleAuction.json"
);

pub async fn deploy(
    keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {
    let deployer = s.read_address()?;
    let beneficiary = s.read_address()?;
    let raw_end_time = s.read_fix_buf(U256_LEN);
    let end_time = U256::from_le_slice(&raw_end_time);
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &deployer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let trx_req = Auction::deploy_builder(pp, end_time, beneficiary)
        .into_transaction_request();

    let receipt = node.send_contract_trx(trx_req, signer, error_handler).await?;

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

pub async fn bid(
    keystore: &KeyStore,
    node: &SzProvider<impl Provider + Clone>,
    s: &mut FramedStream,
) -> WalletResult<()> {
    let bidder = s.read_address()?;
    let contract_addr = s.read_address()?;
    let raw_amount = s.read_fix_buf(U256_LEN);
    let amount = U256::from_le_slice(&raw_amount);
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &bidder.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let bid_trx = Auction::new(contract_addr, pp)
        .bid().value(amount)
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
    let withdrawer = s.read_address()?;
    let contract_addr = s.read_address()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &withdrawer.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let withdraw_trx = Auction::new(contract_addr, pp)
        .withdraw().from(withdrawer)
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
    let admin = s.read_address()?;
    let contract_addr = s.read_address()?;
    let pp = node.get_provider();

    let raw_priv_key = keystore.get_eth_key(&s.uid, &admin.to_string()).await?;
    let priv_key = raw_priv_key.as_signing()?;
    let signer = LocalSigner::from(priv_key.clone());

    let end_trx = Auction::new(contract_addr, pp)
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
    let contract_addr = s.read_address()?;
    let pp = node.get_provider();

    let auction = Auction::new(contract_addr, pp);
    
    let end_time = auction.auctionEndTime().call().await
        .map_err(|e| Errors::ContractCall(e.to_string()))?;
    let beneficiary = auction.beneficiary().call().await
        .map_err(|e| Errors::ContractCall(e.to_string()))?;

    s.mark_successful();
    s.write_address(&beneficiary);
    s.write_buff(end_time.as_le_slice());
    Ok(())
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
