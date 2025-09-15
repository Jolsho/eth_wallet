use alloy::{
    primitives::{Address, FixedBytes, U256}, providers::Provider, sol 
};

use crate::{crypt, handlers::{binary::multi, cmds::Command, json::auction::{ TrxReceipt}, stream::FramedStream}, tests::{self, binary::basic}};

sol!(
    #[sol(rpc)]
    Group,
    "assets/addrs/out/Group.sol/MaddrGroup.json"
);

const NAME_TRX: &str = "multis_bin";

#[tokio::test]
pub async fn multis() {
    let mut t = tests::start_test("multis_bin").await;

    basic::test_register(&mut t.stream,NAME_TRX).await;
    basic::test_login(&mut t.stream, NAME_TRX).await;

    basic::test_recovery(&mut t.stream, 2).await;
    let pp = t.provider.get_provider();

    let addrs = pp.get_accounts().await.unwrap();
    let admin = addrs[0];
    let other = addrs[1];

    let (cont, _res) = test_deploy(&mut t.stream, admin).await.unwrap();
    println!("MULTI CONTRACT DEPLOYED: {}", cont);

    test_set(&mut t.stream, cont, admin, other).await;
    println!("MULTI SET");

    test_set_verified(&mut t.stream, cont, admin, other).await;
    println!("MULTI VERIFIED");

    test_rating(&mut t.stream, cont, other, admin).await;
    println!("MULTI RATED");

    let mult = test_get(&mut t.stream, cont, other).await.unwrap();
    assert_eq!(mult.address, other, "Address should match the one set");
    assert_eq!(mult.username, "JOSHUA", "Username should match the one set");
    assert_eq!(mult.rating, 225, "Rating should be 225");
}


async fn test_deploy(
    s: &mut FramedStream, deployer: Address,
) -> Option<(Address, TrxReceipt)> {

    s.set_opcode(Command::DeployMulti);
    s.write_address(&deployer);
    let cover_charge: [u8;32] = U256::from(100).to_le_bytes();
    s.write_buff(&cover_charge);
    s.flush_buffer(false).await.unwrap();

    if s.was_success().await.unwrap() {
        let contract_addr = s.read_address().unwrap();
        let receipt = s.read_receipt().unwrap();
        Some((contract_addr, receipt))
    } else {
        None
    }
}

async fn test_set(
    s: &mut FramedStream, contract_addr: Address,
    admin: Address, other: Address,
) -> TrxReceipt {
    s.set_opcode(Command::NewMulti);
    s.write_address(&admin);
    s.write_address(&other);
    s.write_address(&contract_addr);

    let cover_charge: [u8;32] = U256::from(1000).to_le_bytes();
    s.write_buff(&cover_charge);
    s.write_str("JOSHUA");

    let protoc_num = multi::IPV6;
    let protocol = FixedBytes::<1>::from_slice(&[protoc_num]);
    s.write_buff(protocol.as_slice());
    let ip = FixedBytes::<16>::from_slice(&crypt::get_random(16));
    s.write_buff(&ip.as_slice());

    s.write_address(&other);
    let peer_id = FixedBytes::<34>::from_slice(&crypt::get_random(34));
    s.write_buff(peer_id.as_slice());
    s.flush_buffer(false).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("Failed to set multi");
    }
    s.read_receipt().unwrap()
}

async fn test_set_verified(
    s: &mut FramedStream, contract_addr: Address, 
    admin: Address, other: Address,
) -> TrxReceipt {
    s.set_opcode(Command::VerifyMulti);
    s.write_address(&admin);
    s.write_address(&contract_addr);
    s.write_address(&other);
    s.flush_buffer(false).await.unwrap();
    
    if !s.was_success().await.unwrap() {
        panic!("Failed to set verified");
    }
    s.read_receipt().unwrap()
}

async fn test_rating(
    s:&mut FramedStream, contract_addr: Address, 
    other: Address, admin: Address, 
) -> TrxReceipt {

    s.set_opcode(Command::RateMulti);
    s.write_address(&admin);
    s.write_address(&contract_addr);
    s.write_address(&other); // rate other address
    let rate = 225 as u8;
    s.write_buff(&[rate]);
    s.flush_buffer(false).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("Failed to rate");
    }
    s.read_receipt().unwrap()
}

#[allow(dead_code)]
struct Mult {
    verified: bool,
    protocol: u8,
    username: String,
    address: Address,
    proxy: Address,
    ip: Vec<u8>,
    rating: u8,
    peer_id: Vec<u8>,
}


async fn test_get(
    s: &mut FramedStream, contract_addr: Address,
    addr: Address,
) -> Option<Mult> {
    s.set_opcode(Command::GetMulti);
    s.write_address(&contract_addr);
    s.write_address(&addr);
    s.flush_buffer(false).await.unwrap();

    if s.was_success().await.unwrap() {
        let verified = s.read_fix_buf(1)[0] != 0;

        let proxy = s.read_address().unwrap();

        let name = s.read_str().unwrap();

        let protocol = s.read_fix_buf(1)[0] as u8;

        let ip = s.read_fix_buf(16);

        let rating = s.read_fix_buf(1)[0] as u8;

        let peer_id = s.read_fix_buf(34);

        Some(Mult {
            verified,
            protocol,
            username: name,
            proxy,
            ip,
            rating,
            peer_id,
            address: addr,
        })
    } else {
        None
    }
}

