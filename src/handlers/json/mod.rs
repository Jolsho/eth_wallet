use std::sync::Arc;

use crate::{auth::store::SessionStore, eth::node::SzProvider, handlers::{cmds::Command, stream::FramedStream}, keys::store::KeyStore, utils::errors::{Errors, WalletResult}};

pub mod auction;
pub mod basic;
pub mod multi;

pub async fn json_dispatcher(
    sesh: &Arc<SessionStore>, keys: &Arc<KeyStore>, 
    node: &SzProvider<impl alloy::providers::Provider + Clone>,
    s: &mut FramedStream
) 
    -> WalletResult<()> 
{
    if let Ok(cmd) = Command::try_from(s.opcode) {

        if s.opcode <= (Command::Close as u8) {

            match cmd {
                Command::Close => s.shutdown().await?,
                _ => return Err(Errors::InvalidCode(s.opcode)),
            }

        } else if s.opcode < (Command::SignSz as u8) {

            match cmd {
                Command::Login => basic::login(sesh, keys, s).await?,
                Command::Register => basic::register(sesh, s).await?,
                _ => return Err(Errors::InvalidCode(s.opcode)),
            }

        } else {
            sesh.try_authorize(&s.uid, &s.ssid).await?;
            match cmd {

                // OTHER
                Command::SignSz => basic::sign_sz(keys, s).await?,
                Command::SendTrx => basic::send_trx(keys, node, s).await?,

                // KEY MANAGEMENT
                Command::NewSz  => basic::new_sz_key(keys, s).await?,
                Command::NewEth => basic::new_eth_key(keys, s).await?,
                Command::NewCha => basic::new_cha_key(keys, s).await?,
                Command::GetCha => basic::get_cha_key(keys, s).await?,
                Command::RecoverEth => basic::derive_eth_keys(keys, node, s).await?,
                Command::RecoverSz => basic::derive_sz_keys(keys, node, s).await?,

                // MULTI
                Command::DeployMulti => multi::deploy(keys, node, s).await?,
                Command::NewMulti => multi::new(keys, node, s).await?,
                Command::VerifyMulti => multi::verify(keys, node, s).await?,
                Command::RateMulti => multi::rate(keys, node, s).await?,
                Command::GetMulti => multi::get_multi(node, s).await?,

                // AUCTION
                Command::DeployAuction => auction::deploy(keys, node, s).await?,
                Command::BidAuction => auction::bid(keys, node, s).await?,
                Command::WithdrawAuction => auction::withdraw(keys, node, s).await?,
                Command::EndAuction => auction::end(keys, node, s).await?,
                Command::GetAuction => auction::get_auction(node, s).await?,

                _ => return Err(Errors::InvalidCode(s.opcode)),
            }
        }
    }
    Ok(()) 
}
