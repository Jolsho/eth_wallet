use alloy::primitives::Address;
use alloy::rpc::types::TransactionReceipt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UnixStream;

use crate::auth::store::SSID_LEN;
use crate::crypt::eip55;
use crate::handlers::json::auction::TrxReceipt;
use crate::{ 
    handlers::cmds::Command,
    handlers::binary::{ADDR_LEN},
    utils::errors::{Errors, WalletResult}
};

pub struct FramedStream {
    w: WriteHalf<UnixStream>,
    r: ReadHalf<UnixStream>,

    buffer: Vec<u8>,
    cursor: usize,

    pub opcode: u8,
    pub uid: String,
    pub format: u8,
    pub ssid: String,
}

const DEFAULT_BUFFER_SIZE: usize = 1000;
const MAX_MESSAGE_SIZE: u32 = 2500; // 2.5 KB

const BINARY_FORM: u8 = 1;
const JSON_FORM: u8 = 2;

#[derive(Deserialize, Serialize)]
struct Packet {
    opcode: u8,
    ssid: String,
    body: Vec<u8>,
}

impl FramedStream {
    pub fn new(stream: UnixStream) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            w: write_half,
            r: read_half,
            uid: "".to_string(),
            opcode: 0,
            cursor: 0,
            format: BINARY_FORM, // default to binary form
            ssid: "".to_string(),
        }
    }

    pub fn is_binary(&self) -> bool {
        self.format == BINARY_FORM
    }

    pub fn is_json(&self) -> bool {
        self.format == JSON_FORM
    }

    pub fn write_len(&mut self, len: u32) { 
        let end = self.cursor + 4;
        if self.buffer.len() < end {
            self.buffer.resize(end + len as usize, 0);
        }
        self.buffer[self.cursor..self.cursor+4].copy_from_slice(&len.to_le_bytes());
        self.cursor += 4;
    }

    pub fn write_str(&mut self, s: &str) { 
        let str_bytes = s.as_bytes();
        self.write_buff_and_len(str_bytes);
    }

    pub fn write_buff(&mut self, buff: &[u8]) { 
        let len = buff.len();
        let end = self.cursor + len;
        if self.buffer.len() < end {
            self.buffer.resize(end, 0);
        }
        self.buffer[self.cursor..end].copy_from_slice(buff);
        self.cursor += len;
    }

    pub fn write_buff_and_len(&mut self, buff: &[u8]) { 
        let len = buff.len();
        self.write_len(len as u32);
        self.write_buff(buff);
    }

    pub fn write_address(&mut self,addr: &Address) {

        let addr_str = eip55::to_eip55(addr.as_slice());
        self.write_buff(addr_str.as_bytes());
    }
    
    pub fn write_address_array(&mut self, addrs: &[Address]) {
        self.write_len(addrs.len() as u32);
        for addr in addrs {
            self.write_address(addr);
        }
    }


    pub fn read_len(&mut self) -> WalletResult<usize> {
        if self.buffer.len() < self.cursor + 4 {
            self.buffer.resize(self.cursor + 4, 0);
        }
        let len = u32::from_le_bytes(self.buffer[self.cursor ..self.cursor + 4]
            .try_into().map_err(|_| Errors::Malformed("Failed to read length".to_string()))?);
        self.cursor += 4;
        Ok(len as usize)
    }

    pub fn read_str(&mut self) -> WalletResult<String> {
        let val = self.read_var_buf()?;
        let str = String::from_utf8(val).map_err(|_| Errors::Malformed("Failed to read string".to_string()))?;
        Ok(str)
    }

    pub fn read_var_buf(&mut self) -> WalletResult<Vec<u8>> {
        let len = self.read_len()?;
        let mut buf = vec![0u8; len];
        buf.copy_from_slice(&self.buffer[self.cursor..self.cursor + len]);
        self.cursor += len;
        Ok(buf)
    }

    pub fn read_fix_buf(&mut self, len: usize) -> Vec<u8> {
        if self.buffer.len() < self.cursor + len {
            self.buffer.resize(self.cursor + len, 0);
        }
        let mut buf = vec![0u8; len];
        buf.copy_from_slice(&self.buffer[self.cursor..self.cursor + len]);
        self.cursor += len;
        buf
    }

    pub fn read_address(&mut self) -> WalletResult<Address> {
        let raw_addr = self.read_fix_buf(ADDR_LEN);

        let raw_addr = String::from_utf8(raw_addr)
            .map_err(|_| Errors::Malformed("Failed to read address".to_string()))?;

        let addr = eip55::from_eip55(&raw_addr)
            .map_err(|_| Errors::Malformed("Failed to parse address".to_string()))?;
        Ok(addr)
    }

    #[cfg(test)]
    pub fn read_address_array(&mut self) -> WalletResult<Vec<Address>> {

        let len = self.read_len()?;
        let mut addrs = Vec::with_capacity(len);
        for _ in 0..len {
            let addr = self.read_address()?;
            addrs.push(addr);
        }
        Ok(addrs)
    }

    #[cfg(test)]
    pub async fn was_success(&mut self) -> WalletResult<bool> {
        self.load_message().await?;
        if self.opcode == Command::Success as u8 {
            Ok(true)

        } else if self.opcode == Command::Error as u8 {
            let e = self.read_str()?;
            println!("ERRORED: {}", e);
            Ok(false)

        } else {
            Err(Errors::ReadResponse(format!("BAD CODE: {}", self.opcode)))
        }
    }

    pub fn mark_successful(&mut self) {
        self.cursor = 0;
        self.opcode = Command::Success as u8;
    }

    // for switching to read and flushing a buffer
    pub async fn load_message(&mut self) -> WalletResult<()> {
        // LENGTH
        let len = self.r.read_u32_le().await
            .map_err(|e| Errors::Malformed(format!("Read length failed: {}", e)))?;

        if len > MAX_MESSAGE_SIZE {
            return Err(Errors::Malformed(format!("Message too large: {}", len)));
        }

        // FORMAT
        let format = self.r.read_u8().await
            .map_err(|_| Errors::Malformed("Read format failed".to_string()))?;

        if format != BINARY_FORM && format != JSON_FORM {
            return Err(Errors::WrongFormat("Load Message".to_string()));
        }
        self.format = format;


        if self.is_binary() {
            // OPCODE
            self.opcode = self.r.read_u8().await
                .map_err(|_| Errors::Malformed("Read opcode failed".to_string()))?;

            // SSID
            let mut ssid = vec![0u8; SSID_LEN];
            self.r.read_exact(&mut ssid).await
                .map_err(|_| Errors::Malformed("Read SSID failed".to_string()))?;

            self.ssid = String::from_utf8(ssid)
                .map_err(|_| Errors::Malformed("SSID is not valid UTF-8".to_string()))?;

        }

        if self.buffer.len() < len as usize {
            self.buffer.resize(len as usize, 0);
        } else if self.buffer.len() > len as usize {
            self.buffer.truncate(len as usize);
        }

        self.r.read_exact(&mut self.buffer).await
            .map_err(|_| Errors::Malformed("Read body failed".to_string()))?;

        if self.is_json() {
            let packet = self.deserialize::<Packet>()?;
            self.opcode = packet.opcode;
            self.buffer = packet.body;
            self.ssid = packet.ssid;
        }

        self.cursor = 0;
        Ok(())
    }

    pub async fn flush_buffer(&mut self, is_json: bool) -> WalletResult<()> {
        if is_json {
            let packet = Packet {
                opcode: self.opcode,
                body: self.buffer[..self.cursor].to_vec(),
                ssid: self.ssid.clone(),
            };
            let json = serde_json::to_vec(&packet)
                .map_err(|_| Errors::Malformed("Failed to serialize packet".to_string()))?;

            self.w.write_u32_le(json.len() as u32).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

            self.w.write_u8(JSON_FORM).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

            self.w.write_all(&json).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

        } else {

            self.w.write_u32_le(self.cursor as u32).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

            self.w.write_u8(BINARY_FORM).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

            self.w.write_u8(self.opcode).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

            if self.ssid.len() != SSID_LEN {
                self.ssid = String::from_utf8(vec![0u8; SSID_LEN])
                    .map_err(|_| Errors::Malformed("SSID is not valid UTF-8".to_string()))?;
            }

            self.w.write_all(self.ssid.as_bytes()).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;

            self.w.write_all(&self.buffer[..self.cursor]).await.map_err(|e|
                Errors::WriteToClient(format!("flush_buffer:write:{}",e)))?;
        }

        self.cursor = 0;
        self.w.flush().await.map_err(|e|
            Errors::WriteToClient(format!("write_str:len:{}",e)))
    }

    pub async fn shutdown(&mut self) -> WalletResult<()> {
        self.w.shutdown().await.map_err(|e|
            Errors::Other(format!("Failed to shutdown:: {}", e.to_string()))
        )
    }

    #[cfg(test)]
    pub fn set_opcode(&mut self, cmd: Command){
        self.cursor = 0;
        self.opcode = cmd as u8;
    }

    pub fn write_error(&mut self, e: Errors) {
        self.cursor = 0;
        self.opcode = Command::Error as u8;
        self.write_str(&e.to_string());
    }

    pub fn write_receipt(&mut self, receipt: &TransactionReceipt) -> WalletResult<()> {
        if self.is_binary() {
            self.write_buff(&receipt.gas_used.to_le_bytes());
            self.write_buff(&receipt.effective_gas_price.to_le_bytes());
            self.write_buff(&receipt.block_number.unwrap_or_default().to_le_bytes());
            self.write_buff(receipt.transaction_hash.as_slice());
            self.write_buff(receipt.block_hash.unwrap_or_default().as_slice());
            self.write_buff(&[true as u8]); // status
        } else {
            self.serialize( &TrxReceipt {
                gas_price: receipt.effective_gas_price,
                gas_used: receipt.gas_used,
                block_number: receipt.block_number.unwrap_or_default(),
                transaction_hash: receipt.transaction_hash,
                block_hash: receipt.block_hash.unwrap_or_default(),
                status: true,
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn read_receipt(&mut self) -> WalletResult<TrxReceipt> {
        if self.is_binary() {
            use alloy::primitives::FixedBytes;

            let gas_used = u64::from_le_bytes(self.read_fix_buf(8)
                .try_into().map_err(|_| Errors::Malformed("Failed to read gas used".to_string()))?);

            let gas_price = u128::from_le_bytes(self.read_fix_buf(16)
                .try_into().map_err(|_| Errors::Malformed("Failed to read gas price".to_string()))?);

            let block_number = u64::from_le_bytes(self.read_fix_buf(8)
                .try_into().map_err(|_| Errors::Malformed("Failed to read block number".to_string()))?);

            let raw_transaction_hash = self.read_fix_buf(32);
            let raw_block_hash = self.read_fix_buf(32);
            let status = self.read_fix_buf(1)[0] == 1;

            let transaction_hash = FixedBytes::<32>::from_slice(&raw_transaction_hash);
            let block_hash = FixedBytes::<32>::from_slice(&raw_block_hash);

            Ok(TrxReceipt {
                gas_used,
                gas_price,
                block_number: block_number,
                transaction_hash: transaction_hash,
                block_hash: block_hash,
                status,
            })
        } else {
            self.deserialize::<TrxReceipt>()
                .map_err(|_| Errors::Malformed("Failed to deserialize receipt".to_string()))
        }
    }

    pub fn deserialize<T: serde::de::DeserializeOwned>(&mut self) -> WalletResult<T> {
        if self.is_json() {
            return serde_json::from_slice(&self.buffer)
                .map_err(|e| Errors::Malformed(format!("Failed to deserialize JSON: {}", e)));
        }
        Err(Errors::WrongFormat("Expected JSON format".to_string()))
    }

    pub fn serialize<T: serde::Serialize>(&mut self, data: &T) -> WalletResult<()> {
        if !self.is_json() {
            self.format = JSON_FORM;
        }
        let json = serde_json::to_vec(data)
            .map_err(|_| Errors::Malformed("Failed to serialize to JSON".to_string()))?;
        self.write_buff(&json);
        Ok(())
    }
}

