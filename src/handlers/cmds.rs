#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Error = 1,
    Success = 2,
    // ...

    Close = 10,

    Login = 11,
    Register = 12,

    SignSz = 13, 
    NewSz = 14,
    NewEth = 15,
    NewCha = 16,
    GetCha = 17,
    SendTrx = 18,
    RecoverEth = 19,
    RecoverSz = 20,

    // MULTI
    DeployMulti = 21,
    NewMulti = 22,
    VerifyMulti = 23,
    RateMulti = 24,
    GetMulti = 25,

    // AUCTION
    DeployAuction = 26,
    BidAuction = 27,
    WithdrawAuction = 28,
    EndAuction = 29,
    GetAuction = 30,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(value: u8) -> Result<Command, ()> {
        match value {
            // BASIC
            1 => Ok(Command::Error),
            2 => Ok(Command::Success),
            // ...
            10 => Ok(Command::Close),

            // MAIN
            11 => Ok(Command::Login),
            12 => Ok(Command::Register),

            13 => Ok(Command::SignSz),
            14 => Ok(Command::NewSz),
            15 => Ok(Command::NewEth),
            16 => Ok(Command::NewCha),
            17 => Ok(Command::GetCha),
            18 => Ok(Command::SendTrx),
            19 => Ok(Command::RecoverEth),
            20 => Ok(Command::RecoverSz),

            // MULTI
            21 => Ok(Command::DeployMulti),
            22 => Ok(Command::NewMulti),
            23 => Ok(Command::VerifyMulti),
            24 => Ok(Command::RateMulti),
            25 => Ok(Command::GetMulti),

            // AUCTION
            26 => Ok(Command::DeployAuction),
            27 => Ok(Command::BidAuction),
            28 => Ok(Command::WithdrawAuction),
            29 => Ok(Command::EndAuction),
            30 => Ok(Command::GetAuction),

            _ => Err(()),
        }
    }
}


