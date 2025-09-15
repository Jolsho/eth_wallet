use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
     primitives::{Address, U256}, providers::{ext::AnvilApi, Provider}
};


use crate::{handlers::{ cmds::Command, json::auction::{AuctionBid, ContractCall, DeployAuction, DeployContractResponse, TrxReceipt}, stream::FramedStream}, tests::{self, json::basic}};

const NAME_TRX: &str = "auction_json";

#[tokio::test]
pub async fn auction() {
    let t = tests::start_test("auction_json").await;
    let mut stream = t.stream;

    let _pp = t.provider.get_provider();

    basic::test_register(&mut stream,NAME_TRX).await;
    basic::test_login(&mut stream, NAME_TRX).await;

    basic::test_recovery(&mut stream, 4).await;
    let pp = t.provider.get_provider();

    let addrs = pp.get_accounts().await.unwrap();
    let deployer = addrs[0];
    let bidder = addrs[1];
    let reverter = addrs[2];
    let beneficiary = addrs[3];

    let bene_balance1 = pp.get_balance(beneficiary).await.unwrap();
    let rev_balance1 = pp.get_balance(reverter).await.unwrap();
    let mut reverter_gas_used = U256::from(0);

    let res = test_deploy(&mut stream, deployer, beneficiary).await.unwrap();
    println!("AUCTION CONTRACT DEPLOYED: {}", res.contract_address);

    let mut rec = test_bid(&mut stream, reverter, res.contract_address, 100000).await;
    reverter_gas_used += U256::from(rec.gas_used as u128 * rec.gas_price);
    println!("REVERTER BIDDING");

    let bid_amount = 150000;
    let _ = test_bid(&mut stream, bidder, res.contract_address, bid_amount).await;
    println!("BIDDER BIDDING");

    rec = test_withdraw(&mut stream, reverter, res.contract_address).await;
    reverter_gas_used += U256::from(rec.gas_used as u128 * rec.gas_price);
    println!("REVERTER WITHDRAWING");

    // fast forward time to end the auction
    pp.anvil_set_next_block_timestamp(current_unix_time_secs() + 10).await.unwrap();
    pp.anvil_mine(Some(2),None).await.unwrap();

    let _ = test_end(&mut stream, res.contract_address, bidder).await;
    println!("AUCTION ENDED");

    let bene_balance2 = pp.get_balance(beneficiary).await.unwrap();
    assert!(bene_balance2 == bene_balance1 + U256::from(bid_amount), "Beneficiary balance should be increased by the bid amount");

    // reverters balance == their initial balance - gas used
    let rev_balance2 = pp.get_balance(reverter).await.unwrap();
    assert!(rev_balance1 == rev_balance2 + reverter_gas_used, 
        "Reverter's balance should be their initial balance minus gas used"
    );
}

fn current_unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

async fn test_deploy(
    s: &mut FramedStream, 
    deployer: Address,
    beneficiary: Address,
) -> Option<DeployContractResponse> {

    s.set_opcode(Command::DeployAuction);
    s.serialize(&DeployAuction {
        deployer,
        beneficiary,
        end_time: U256::from(8), // 8 seconds from now
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        Some(s.deserialize::<DeployContractResponse>().unwrap())
    } else {
        None
    }
}

async fn test_bid(
    s: &mut FramedStream, 
    bidder: Address, 
    contract_addr: Address,
    amount: u64,
) -> TrxReceipt {
    s.set_opcode(Command::BidAuction);
    s.serialize(&AuctionBid {
        bidder,
        contract_addr,
        amount: U256::from(amount),
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("Bid failed");
    }
    s.deserialize::<TrxReceipt>().unwrap()
}

async fn test_withdraw(
    s: &mut FramedStream, 
    withdrawer: Address, 
    contract_addr: Address,
) -> TrxReceipt {
    s.set_opcode(Command::WithdrawAuction);
    s.serialize(&ContractCall {
        address: withdrawer,
        contract_addr,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("Withdraw failed");
    }
    s.deserialize::<TrxReceipt>().unwrap()
}

async fn test_end(
    s: &mut FramedStream, 
    contract_addr: Address,
    addr: Address,
) -> TrxReceipt {
    s.set_opcode(Command::EndAuction);
    s.serialize(&ContractCall {
        address: addr,
        contract_addr,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("End auction failed");
    }
    s.deserialize::<TrxReceipt>().unwrap()
}
