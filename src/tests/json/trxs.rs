use alloy::{
    primitives::{U256}, 
    providers::{Provider }
};
use alloy_node_bindings::{ WEI_IN_ETHER};

use crate::{  handlers::{cmds::Command, json::{auction::TrxReceipt, basic::SendTrxRequest}}, tests::{self, json::basic} };

const NAME_TRX: &'static str = "nametrx";

#[tokio::test]
async fn trx() {
    let t = tests::start_test("trx_json").await;
    let mut s= t.stream;

    let pp = t.provider.get_provider();

    basic::test_register(&mut s,NAME_TRX).await;
    basic::test_login(&mut s, NAME_TRX).await;
    basic::test_recovery(&mut s, 2).await;

    let new_addr = basic::test_eth_key(&mut s).await;

    let rbalance1 = pp.get_balance(new_addr).await.unwrap();
    assert!(rbalance1 == U256::from(0), "BALANCE1 SHOULD BE 0 ETH");

    // FUND CREATED KEY
    let a1 = pp.get_accounts().await.unwrap()[0];
    let sbalance1 = pp.get_balance(a1).await.unwrap();

    s.set_opcode(Command::SendTrx);
    s.serialize(&SendTrxRequest {
        from: a1,
        to: new_addr,
        amount: U256::from(2) * WEI_IN_ETHER,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("SEND TRX FAILED: {}", s.read_str().unwrap());
    }
    let rec = s.deserialize::<TrxReceipt>().unwrap();

    let spent = U256::from(rec.gas_used) * U256::from(rec.gas_price);
    let sbalance2 = pp.get_balance(a1).await.unwrap() ;

    let dif = sbalance2 - (sbalance1 - ((U256::from(2) * WEI_IN_ETHER) + spent));
    println!("dif: {}", dif);
    assert!(dif == U256::from(0), "SENDER BALANCE SHOULD BE 2 ETH LESS THAN BEFORE, SPENT: {}", spent);

    let rbalance2 = pp.get_balance(new_addr).await.unwrap();
    assert!(rbalance2 == U256::from(2) * WEI_IN_ETHER, "BALANCE2 SHOULD BE 2 ETH");

    println!("RECEIVE: {} -> {}", 
        format_ether_2dp(rbalance1), 
        format_ether_2dp(rbalance2)
    );
    println!("SENDER: {} -> {}", 
        format_ether_2dp(sbalance1), 
        format_ether_2dp(sbalance2)
    );
}

pub fn format_ether_2dp(wei: U256) -> String {
    // Get whole ETH part
    let eth = wei / WEI_IN_ETHER;

    // Get the fractional wei remainder, and convert to 2 decimal digits
    let remainder = wei % WEI_IN_ETHER;
    let fractional = (remainder * U256::from(100)) / WEI_IN_ETHER;

    // Pad fractional part with leading zeros if needed (e.g., "04" instead of "4")
    format!("{}.{}", eth, format!("{:0>2}", fractional))
}

