use tokio;
use chacha20poly1305::Key;
use alloy::{primitives::{Address, B256}, signers::Signature};

use crate::{
     crypt::{self, eip55}, handlers::{cmds::Command, binary::{HASH_LEN, SIG_LEN}, stream::FramedStream}, keys::KeyType, tests::{self} 
};


const NAME_BASIC: &'static str = "name_bin";
pub const PASSWORD: &'static str = "pass";
pub const SECRET: &'static str = "secret";

#[tokio::test]
async fn basic() {
    let t = tests::start_test("basic_bin").await;
    let mut stream = t.stream;

    test_register(&mut stream, NAME_BASIC).await;
    test_login(&mut stream, NAME_BASIC).await;
    println!("LOGIN SUCCESSFUL");

    test_sz_key(&mut stream).await;
    println!("SZ COMPLETE");

    test_cha(&mut stream).await;
    println!("CHACHA COMPLETE");

    println!("SUCCESS!!!");
}

pub async fn test_register( stream: &mut FramedStream, name: &str) {
    stream.set_opcode(Command::Register);
    stream.write_str(name);
    stream.write_str(PASSWORD);
    stream.write_str(SECRET);
    stream.flush_buffer(false).await.unwrap();

    if stream.was_success().await.unwrap() {
        let _mnemon = stream.read_str();
        println!("REGISTRATION SUCCESSFUL");
    } else {
        panic!("REGISTRATION FAILED");
    }
}

pub async fn test_login(stream: &mut FramedStream, name: &str) {
    stream.set_opcode(Command::Login);
    stream.write_str(name);
    stream.write_str(PASSWORD);
    stream.flush_buffer(false).await.unwrap();

    if stream.was_success().await.unwrap() {
        stream.ssid = stream.read_str().unwrap();
    } else {
        println!("ALREADY LOGGED IN ERROR == SUCCESSFUL");
    }
}

async fn test_sz_key(stream: &mut FramedStream) {
    stream.set_opcode(Command::NewSz);
    stream.flush_buffer(false).await.unwrap();

    if stream.was_success().await.unwrap() {
        let addr = stream.read_address().unwrap();

        let msg = Vec::from("hello tester");

        stream.set_opcode(Command::SignSz);
        stream.write_buff_and_len(&msg);
        stream.write_address(&addr);
        stream.flush_buffer(false).await.unwrap();

        if stream.was_success().await.unwrap() {
            let raw_sig = stream.read_fix_buf(SIG_LEN);
            let hash = B256::from_slice(&stream.read_fix_buf(HASH_LEN));
            let sig = Signature::from_raw(&raw_sig).unwrap();
            let v_key = sig.recover_from_prehash(&hash).unwrap();
            let raw_addr1 = crypt::derive_address(&v_key);
            let addr1 = eip55::to_eip55(raw_addr1.as_slice());

            assert!(addr.to_string() == addr1);
        } else {
            panic!("SIGN SZ FAILED")
        }
    } else {
        panic!("NEW SZ FAILED")
    }
}

async fn test_cha(stream: &mut FramedStream) {
    stream.set_opcode(Command::NewCha);
    stream.flush_buffer(false).await.unwrap();

    if stream.was_success().await.unwrap() {
        let key_id = stream.read_str().unwrap();
        let raw_key = stream.read_var_buf().unwrap();
        let key = KeyType::Cha(*Key::from_slice(&raw_key));

        let message = "hello worlds its MEEEE!!!";
        let c_key = key.as_chacha().unwrap();
        let (nonce, cipher) = crypt::cha::encrypt_str(c_key, message).unwrap();

        stream.set_opcode(Command::GetCha);
        stream.write_str(&key_id);
        stream.flush_buffer(false).await.unwrap();

        if stream.was_success().await.unwrap() {
            let raw_key1 = stream.read_var_buf().unwrap();
            let key1 = KeyType::Cha(*Key::from_slice(&raw_key1));
            let m1 = crypt::cha::decrypt_str(key1.as_chacha().unwrap(), &nonce, &cipher).unwrap();
            assert!(message == m1);
        } else {
            panic!("GET CHA FAILED")
        }
    } else {
        panic!("NEW CHA FAILED")
    }
}

pub async fn test_eth_key(stream: &mut FramedStream) -> Address {
    stream.set_opcode(Command::NewEth);
    stream.flush_buffer(false).await.unwrap();

    if stream.was_success().await.unwrap() {
        let addr = stream.read_address().unwrap();

        let msg = Vec::from("hello tester");

        stream.set_opcode(Command::SignSz);
        stream.write_buff_and_len(&msg);
        stream.write_address(&addr);
        stream.flush_buffer(false).await.unwrap();

        if stream.was_success().await.unwrap() {
            let raw_sig = stream.read_fix_buf(SIG_LEN);
            let hash = B256::from_slice(&stream.read_fix_buf(HASH_LEN));
            let sig = Signature::from_raw(&raw_sig).unwrap();
            let v_key = sig.recover_from_prehash(&hash).unwrap();
            let raw_addr1 = crypt::derive_address(&v_key);
            let addr1 = eip55::to_eip55(raw_addr1.as_slice());
            assert!(addr.to_string() == addr1);
            return raw_addr1
        } else {
            panic!("SIGN ETH FAILED");
        }
    } else {
        panic!("NEW ETH FAILED");
    }
}

pub async fn test_recovery(stream: &mut FramedStream, count: u8) {
    let mnemonic = "test test test test test test test test test test test junk";
    let password = "";
    stream.set_opcode(Command::RecoverEth);
    stream.write_str(mnemonic);
    stream.write_str(password);
    stream.write_buff(&[count]);
    stream.flush_buffer(false).await.unwrap();

    if !stream.was_success().await.unwrap() {
        panic!("RECOVERY FAILED: {}", stream.read_str().unwrap());
    }
    let _addrs = stream.read_address_array().unwrap();
    println!("RECOVERY SUCCESSFUL");
}
