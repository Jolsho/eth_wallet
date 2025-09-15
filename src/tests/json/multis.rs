use alloy::{
    primitives::{Address, FixedBytes, U256}, providers::Provider, sol 
};

use crate::{crypt, handlers::{self, cmds::Command, json::{auction::{DeployContractResponse, TrxReceipt}, multi}, stream::FramedStream}, tests::{self, json::basic}};

sol!(
    #[sol(rpc)]
    Group,
    "assets/addrs/out/Group.sol/MaddrGroup.json"
);

const NAME_TRX: &str = "multis_json";

#[tokio::test]
pub async fn multis() {
    let mut t = tests::start_test("multis_json").await;

    basic::test_register(&mut t.stream,NAME_TRX).await;
    basic::test_login(&mut t.stream, NAME_TRX).await;

    basic::test_recovery(&mut t.stream, 2).await;
    let pp = t.provider.get_provider();

    let addrs = pp.get_accounts().await.unwrap();
    let admin = addrs[0];
    let other = addrs[1];

    let res = test_deploy(&mut t.stream, admin).await.unwrap();
    println!("MULTI CONTRACT DEPLOYED: {}", res.contract_address);

    _ = test_set(&mut t.stream, res.contract_address, admin, other).await;
    println!("MULTI SET");

    _ = test_set_verified(&mut t.stream, res.contract_address, admin, other).await;
    println!("MULTI VERIFIED");

    _ = test_rating(&mut t.stream, res.contract_address, other, admin).await;
    println!("MULTI RATED");

    let mult = test_get(&mut t.stream, res.contract_address, other).await.unwrap();
    assert_eq!(mult.addr, other, "Address should match the one set");
    assert_eq!(mult.username, "JOSHUA", "Username should match the one set");
    assert_eq!(mult.rating, 225, "Rating should be 225");
}


async fn test_deploy(
    s: &mut FramedStream, deployer: Address,
) -> Option<DeployContractResponse> {

    s.set_opcode(Command::DeployMulti);
    s.serialize(&multi::DeployMulti {
        deployer,
        cover_charge: U256::from(100),
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        Some(s.deserialize::<DeployContractResponse>().unwrap())
    } else {
        None
    }
}

async fn test_set(
    s: &mut FramedStream, contract_addr: Address,
    admin: Address, other: Address,
) -> TrxReceipt {
    s.set_opcode(Command::NewMulti);
    s.serialize(&multi::NewMulti {
        addr: admin,
        addr_to_put: other,
        proxy: Address::ZERO,
        amount: U256::from(1000),
        username: "JOSHUA".to_string(),
        protocol: FixedBytes::<1>::from_slice(&[handlers::binary::multi::IPV6]),
        ip: FixedBytes::<16>::from_slice(&crypt::get_random(16)),
        peer_id: FixedBytes::<34>::from_slice(&crypt::get_random(34)),
        contract_addr,
        rating: 0,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("Failed to set multi");
    }
    s.deserialize::<TrxReceipt>().unwrap()
}

async fn test_set_verified(
    s: &mut FramedStream, contract_addr: Address, 
    admin: Address, other: Address,
) -> TrxReceipt {
    s.set_opcode(Command::VerifyMulti);
    s.serialize(&multi::AddressTriple {
        signer: admin,
        addr: other,
        contract_addr,
        number: 0,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();
    
    if !s.was_success().await.unwrap() {
        panic!("Failed to set verified");
    }
    s.deserialize::<TrxReceipt>().unwrap()
}

async fn test_rating(
    s:&mut FramedStream, contract_addr: Address, 
    other: Address, admin: Address,
) -> TrxReceipt {

    s.set_opcode(Command::RateMulti);
    s.serialize(&multi::AddressTriple {
        signer: admin,
        addr: other,
        contract_addr,
        number: 225,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("Failed to rate");
    }
    s.deserialize::<TrxReceipt>().unwrap()
}

async fn test_get(
    s: &mut FramedStream, contract_addr: Address,
    addr: Address,
) -> Option<multi::NewMulti> {
    s.set_opcode(Command::GetMulti);
    s.serialize(&multi::AddressTriple {
        signer: Address::ZERO, // Not used in this context
        addr,
        contract_addr,
        number: 0, // Not used in this context
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        Some(s.deserialize::<multi::NewMulti>().unwrap())
    } else {
        None
    }
}
