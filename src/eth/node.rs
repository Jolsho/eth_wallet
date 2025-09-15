
use alloy::{
    consensus::SignableTransaction, network::{ EthereumWallet, TransactionBuilder }, primitives::{ Address, Bytes, U256 }, providers::Provider, rpc::types::{ TransactionReceipt, TransactionRequest }, signers::{local::LocalSigner, Signer}, sol_types, transports::RpcError
};
use k256::ecdsa::SigningKey;

use crate::{ utils::errors::{Errors, WalletResult}};

#[derive(Clone)]
pub struct SzProvider<P: Provider + Clone> {
    provider: P,
}

impl<P: Provider + Clone> SzProvider<P> {
    pub fn new(provider: P) -> Self { Self { provider } }
    pub fn get_provider(&self) -> P { self.provider.clone() }

    pub async fn send_contract_trx<E: sol_types::SolInterface>(&self,
        mut tx_req: TransactionRequest, signer: LocalSigner<SigningKey>,
        error_handler: impl Fn(Option<E>, Option<Bytes>) -> Errors,
    ) ->  WalletResult<TransactionReceipt>
    {
        let est = self.provider.estimate_eip1559_fees().await
            .map_err(|e| Errors::TrxBuilder(e.to_string()))?;

        let nonce = self.provider.get_transaction_count(signer.address()).await
            .map_err(|e| Errors::TrxBuilder(e.to_string()))?;

        let chain_id = self.provider.get_chain_id().await
            .map_err(|e| Errors::TrxBuilder(e.to_string()))?;

        tx_req.nonce = Some(nonce);
        tx_req.chain_id = Some(chain_id);
        tx_req.max_priority_fee_per_gas = Some(est.max_priority_fee_per_gas);
        tx_req.max_fee_per_gas = Some(est.max_fee_per_gas);
        tx_req.from = Some(signer.address());

        let limit = self.provider.estimate_gas(tx_req.clone()).await
            .map_err(|e| {
                    match e{
                        RpcError::ErrorResp(err) => {
                            let data = err.as_revert_data();
                            let error = err.as_decoded_interface_error::<E>();
                            return error_handler(error, data);
                        },
                        _ => return Errors::TrxBuilder(e.to_string()),
                    }
            })?;

        tx_req.gas = Some(limit);

        let unsigned = tx_req.build_unsigned()
            .map_err(|e| Errors::TrxBuilder(e.to_string()))?;

        let hash = unsigned.signature_hash();
        let sig = signer.sign_hash(&hash).await
            .map_err(|e| Errors::SignMsg(e.to_string()))?;

        let signed = unsigned.into_signed(sig);

        self.provider.send_tx_envelope(signed.into()).await
            .map_err(|e| Errors::SendTrx(e.to_string()))?
            .get_receipt().await
            .map_err(|e| Errors::GetReceipt(e.to_string()))
    }

    pub async fn send_trx(&self, 
        signer: LocalSigner<SigningKey>,
        to: Address, amount: U256,
    ) -> Result<TransactionReceipt,Box<dyn std::error::Error>> 
    {
        let addr = signer.address();
        let wallet = EthereumWallet::from(signer);
        let est = self.provider.estimate_eip1559_fees().await?;
        let quantity = U256::from(amount);

        let tx = TransactionRequest::default()
            .with_to(to).with_value(quantity)
            .with_nonce(self.provider.get_transaction_count(addr).await?)
            .with_chain_id(self.provider.get_chain_id().await?)
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(est.max_priority_fee_per_gas)
            .with_max_fee_per_gas(est.max_fee_per_gas)
            .build(&wallet).await?;

        // Send the transaction and wait for the broadcast
        let pending_tx = self.provider.send_tx_envelope(tx).await?;

        // Wait for the transaction to be included and get the receipt
        let receipt = pending_tx.get_receipt().await?;
        Ok(receipt)
    }
}
