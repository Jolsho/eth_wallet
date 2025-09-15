use chacha20poly1305::Key;
use alloy::{primitives::{Address}};

use crate::{
     crypt::{self, eip55}, handlers::{ cmds::Command, json::basic::{ChaKeyResponse, LoginRequest, LoginResponse, NewKeyResponse, RecoverKeysRequest, RecoverKeysResponse, RegisterRequest, RegisterResponse, SignRequest, SignResponse}, stream::FramedStream}, keys::KeyType, tests::{self} 
};


const NAME_BASIC: &'static str = "name_json";
pub const PASSWORD: &'static str = "pass";
pub const SECRET: &'static str = "secret";

#[tokio::test]
async fn basic() {
    let t = tests::start_test("basic_json").await;
    let mut stream = t.stream;

    test_register(&mut stream, NAME_BASIC).await;
    test_login(&mut stream, NAME_BASIC).await;
    println!("LOGIN SUCCESSFUL");

    test_sz_key(&mut stream).await;
    println!("SZ COMPLETE");

    test_cha(&mut stream).await;
    println!("CHACHA COMPLETE");
}

pub async fn test_register(s: &mut FramedStream, name: &str) {
    s.set_opcode(Command::Register);
    s.serialize(&RegisterRequest {
        name: name.to_string(),
        pass: PASSWORD.to_string(),
        secret: SECRET.to_string(),
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        let _res = s.deserialize::<RegisterResponse>().unwrap();
        println!("REGISTRATION SUCCESSFUL");
    } else {
        panic!("REGISTRATION FAILED");
    }
}

pub async fn test_login(s: &mut FramedStream, name: &str) {
    s.set_opcode(Command::Login);
    s.serialize(&LoginRequest {
        name: name.to_string(),
        pass: PASSWORD.to_string(),
    }).unwrap();
    
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        let res = s.deserialize::<LoginResponse>().unwrap();
        s.ssid = res.ssid;
    } else {
        println!("ALREADY LOGGED IN ERROR == SUCCESSFUL");
    }
}

async fn test_sz_key(s: &mut FramedStream) {
    s.set_opcode(Command::NewSz);
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        let res1 = s.deserialize::<NewKeyResponse>().unwrap();

        let msg = Vec::from("hello tester");

        s.set_opcode(Command::SignSz);
        s.serialize(&SignRequest {
            msg: msg.clone(),
            addr: res1.address.clone(),
        }).unwrap();
        s.flush_buffer(true).await.unwrap();

        if s.was_success().await.unwrap() {
            let res = s.deserialize::<SignResponse>().unwrap();

            let v_key = res.sig.recover_from_prehash(&res.hash).unwrap();
            let raw_addr1 = crypt::derive_address(&v_key);
            let addr1 = eip55::to_eip55(raw_addr1.as_slice());

            assert!(res1.address.to_string() == addr1);
        } else {
            panic!("SIGN SZ FAILED")
        }
    } else {
        panic!("NEW SZ FAILED")
    }
}

async fn test_cha(s: &mut FramedStream) {
    s.set_opcode(Command::NewCha);
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        let mut res = s.deserialize::<ChaKeyResponse>().unwrap();
        let mut key = KeyType::Cha(*Key::from_slice(&res.cha_key));

        let message = "hello worlds its MEEEE!!!";
        let (nonce, cipher) = crypt::cha::encrypt_str(
            key.as_chacha().unwrap(), message).unwrap();

        s.set_opcode(Command::GetCha);
        s.serialize(&res).unwrap();
        s.flush_buffer(true).await.unwrap();

        if s.was_success().await.unwrap() {
            res = s.deserialize::<ChaKeyResponse>().unwrap();
            key = KeyType::Cha(*Key::from_slice(&res.cha_key));
            let m1 = crypt::cha::decrypt_str(
                key.as_chacha().unwrap(), &nonce, &cipher).unwrap();
            assert!(message == m1);
        } else {
            panic!("GET CHA FAILED")
        }
    } else {
        panic!("NEW CHA FAILED")
    }
}

pub async fn test_eth_key(s: &mut FramedStream) -> Address {
    s.set_opcode(Command::NewEth);
    s.flush_buffer(true).await.unwrap();

    if s.was_success().await.unwrap() {
        let res1 = s.deserialize::<NewKeyResponse>().unwrap();

        let msg = Vec::from("hello tester");

        s.set_opcode(Command::SignSz);
        s.serialize(&SignRequest {
            msg: msg.clone(),
            addr: res1.address.clone(),
        }).unwrap();
        s.flush_buffer(true).await.unwrap();

        if s.was_success().await.unwrap() {
            let res = s.deserialize::<SignResponse>().unwrap();
            let v_key = res.sig.recover_from_prehash(&res.hash).unwrap();
            let raw_addr1 = crypt::derive_address(&v_key);
            let addr1 = eip55::to_eip55(raw_addr1.as_slice());
            assert!(res1.address.to_string() == addr1);
            return raw_addr1
        } else {
            panic!("SIGN ETH FAILED");
        }
    } else {
        panic!("NEW ETH FAILED");
    }
}

pub async fn test_recovery(s: &mut FramedStream, count: u8) {
    let mnemonic = "test test test test test test test test test test test junk";
    let password = "";
    s.set_opcode(Command::RecoverEth);
    s.serialize::<RecoverKeysRequest>(&RecoverKeysRequest {
        mnemonic: mnemonic.to_string(),
        password: password.to_string(),
        count: count as i64,
    }).unwrap();
    s.flush_buffer(true).await.unwrap();

    if !s.was_success().await.unwrap() {
        panic!("RECOVERY FAILED: {}", s.read_str().unwrap());
    }
    let _res = s.deserialize::<RecoverKeysResponse>().unwrap();
    println!("RECOVERY SUCCESSFUL");
}
