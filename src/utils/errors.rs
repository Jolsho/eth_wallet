use std::{fmt};


pub type WalletResult<T> = Result<T,Errors>;

#[derive(Debug)]
#[allow(unused)]
pub enum Errors{
    // DB
    FailedPut(String),
    BadTable(String),
    QueryErr(String),
    ExecErr(String),
    Interact(String),

    // KEY
    GenerateErr(String),
    FailedEncKey(String),
    FailedDecKey(String),
    FromSlice(String),
    InvalidKeyType,
    SignMsg(String),

    // AUTH
    InvalidCredentials,
    NeedSessionId,
    Unauthorized,
    UsernameExists,
    NoMetaData,

    // OTHER
    Other(String),
    MnemonErr(String),
    DecodeHex(String),
    Decode64(String),
    Encryption(String),
    PlainUTF8(String),

    // STREAMS
    InvalidCode(u8),
    WriteToClient(String),
    ReadResponse(String),
    Malformed(String),
    WrongFormat(String),

    // ETH
    SendTrx(String),
    NodeError(String),
    TrxBuilder(String),
    GetReceipt(String),
    ContractCall(String),
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // DB
            Errors::FailedPut(val) => write!(f, "DB_PUT: {}",val),
            Errors::QueryErr(val) => write!(f, "DB_QUERY: {}",val),
            Errors::ExecErr(val) => write!(f, "DB_EXEC: {}",val),
            Errors::BadTable(val) => write!(f, "WRONG_TABLE: {}",val),
            Errors::Interact(val) => write!(f, "DB_INTERACTION: {}",val),

            // KEYS
            Errors::FailedEncKey(val) => write!(f, "ENC_KEY: {}",val),
            Errors::FailedDecKey(val) => write!(f, "DEC_KEY: {}",val),
            Errors::GenerateErr(val) => write!(f, "GEN_KEY: {}",val),
            Errors::FromSlice(val) => write!(f, "KEY_FROM_SLICE: {}",val),
            Errors::InvalidKeyType => write!(f, "INVALID KEY TYPE"),
            Errors::SignMsg(val) => write!(f, "SIGN_MSG: {}", val),

            // other
            Errors::NoMetaData => write!(f, "Couldnt find key generation data."),
            Errors::UsernameExists => write!(f, "Username already exists."),
            Errors::InvalidCredentials => write!(f, "Invalid Credentials"),
            Errors::NeedSessionId => write!(f, "Need Session Id"),
            Errors::Unauthorized => write!(f, "Bad Sessions Id Attempt"),
            Errors::Other(msg) => write!(f, "{}", msg),

            Errors::MnemonErr(val) => write!(f, "GEN_MNEMONIC: {}", val),
            Errors::DecodeHex(val) => write!(f, "DECODE_HEX: {}", val),
            Errors::Decode64(val) => write!(f, "DECODE_b64: {}", val),
            Errors::Encryption(val) => write!(f, "ENCRYPT_CHA: {}", val),
            Errors::PlainUTF8(val) => write!(f, "DECODE_UTF8: {}", val),

            // STREAMS
            Errors::InvalidCode(code) => write!(f, "INVALID_CODE: {}", code),
            Errors::WriteToClient(val) => write!(f, "WRITE_2_CLIENT: {}", val),
            Errors::ReadResponse(val) => write!(f, "READ_RESPONSE: {}", val),
            Errors::Malformed(val) => write!(f, "MALFORMED_PACKET: {}", val),
            Errors::WrongFormat(val) => write!(f, "WRONG_FORMAT: {}", val),

            // ETH
            Errors::SendTrx(val) => write!(f, "SEND_TRX: {}", val),
            Errors::NodeError(val) => write!(f, "NODE_ERROR: {}", val),
            Errors::TrxBuilder(val) => write!(f, "TRX_BUILDER: {}", val),
            Errors::GetReceipt(val) => write!(f, "GET_RECEIPT: {}", val),
            Errors::ContractCall(val) => write!(f, "{}", val),
        }
    }
}
impl std::error::Error for Errors {}

