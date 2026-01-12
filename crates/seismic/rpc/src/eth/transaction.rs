//! Loads and formats Seismic transaction RPC response.

use super::ext::SeismicTransaction;
use crate::{
    eth::{SeismicNodeCore, SignableSeismicTransactionRequest},
    utils::recover_typed_data_request,
    SeismicEthApi, SeismicEthApiError,
};
use alloy_consensus::{transaction::Recovered, Transaction as _};
use alloy_primitives::{Bytes, Signature, B256};
use alloy_rpc_types_eth::{Transaction, TransactionInfo};
use reth_rpc_convert::transaction::{RpcTxConverter, SimTxConverter};
use reth_rpc_eth_api::{
    helpers::{spec::SignersForRpc, EthTransactions, LoadTransaction},
    FromEthApiError, RpcConvert, RpcNodeCore,
};
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError};
use reth_seismic_primitives::SeismicTransactionSigned;
use reth_storage_api::{BlockReader, BlockReaderIdExt, ProviderTx};
use reth_transaction_pool::{
    AddedTransactionOutcome, PoolTransaction, TransactionOrigin, TransactionPool,
};
use seismic_alloy_consensus::{Decodable712, SeismicTxEnvelope, TypedDataRequest};
use seismic_alloy_rpc_types::SeismicTransactionRequest;

impl<N, Rpc> EthTransactions for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
    fn signers(&self) -> &SignersForRpc<Self::Provider, Self::NetworkTypes> {
        self.inner.signers()
    }

    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        let recovered = recover_raw_transaction(&tx)?;
        tracing::debug!(target: "reth-seismic-rpc::eth", ?recovered, "serving seismic_eth_api::send_raw_transaction");

        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        // submit the transaction to the pool with a `Local` origin
        let AddedTransactionOutcome { hash, .. } = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        Ok(hash)
    }
}

impl<N, Rpc> SeismicTransaction for SeismicEthApi<N, Rpc>
where
    Self: LoadTransaction<Provider: BlockReaderIdExt>,
    // N: RpcNodeCore,
    N: SeismicNodeCore<
        Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>
    >,
    <<<SeismicEthApi<N, Rpc> as RpcNodeCore>::Pool as TransactionPool>::Transaction as PoolTransaction>::Pooled: Decodable712,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
    async fn send_typed_data_transaction(&self, tx: TypedDataRequest) -> Result<B256, Self::Error> {
        let recovered = recover_typed_data_request(&tx)?;

        // broadcast raw transaction to subscribers if there is any.
        // TODO: maybe we need to broadcast the encoded tx instead of the recovered tx
        // when other nodes receive the raw bytes the hash they recover needs to be
        // type
        // self.broadcast_raw_transaction(recovered.to);

        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        // submit the transaction to the pool with a `Local` origin
        let AddedTransactionOutcome { hash, .. } = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        Ok(hash)
    }
}

impl<N, Rpc> LoadTransaction for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
}

/// Seismic RPC transaction converter that implements Debug
#[derive(Clone, Debug)]
pub struct SeismicRpcTxConverter;

impl SeismicRpcTxConverter {
    /// Creates a new converter
    pub const fn new() -> Self {
        Self
    }
}

/// Seismic simulation transaction converter that implements Debug
#[derive(Clone, Debug)]
pub struct SeismicSimTxConverter;

impl SeismicSimTxConverter {
    /// Creates a new converter
    pub const fn new() -> Self {
        Self
    }
}

impl RpcTxConverter<SeismicTransactionSigned, Transaction<SeismicTxEnvelope>, TransactionInfo>
    for SeismicRpcTxConverter
{
    type Err = SeismicEthApiError;

    fn convert_rpc_tx(
        &self,
        tx: SeismicTransactionSigned,
        signer: alloy_primitives::Address,
        tx_info: TransactionInfo,
    ) -> Result<Transaction<SeismicTxEnvelope>, Self::Err> {
        let tx_envelope: SeismicTxEnvelope = tx.into();
        let recovered_tx = Recovered::new_unchecked(tx_envelope, signer);

        let TransactionInfo {
            block_hash, block_number, index: transaction_index, base_fee, ..
        } = tx_info;

        let effective_gas_price = base_fee
            .map(|base_fee| {
                recovered_tx.effective_tip_per_gas(base_fee).unwrap_or_default() + base_fee as u128
            })
            .unwrap_or_else(|| recovered_tx.max_fee_per_gas());

        Ok(Transaction::<SeismicTxEnvelope> {
            inner: recovered_tx,
            block_hash,
            block_number,
            transaction_index,
            effective_gas_price: Some(effective_gas_price),
        })
    }
}

impl SimTxConverter<alloy_rpc_types_eth::TransactionRequest, SeismicTransactionSigned>
    for SeismicSimTxConverter
{
    type Err = SeismicEthApiError;

    fn convert_sim_tx(
        &self,
        tx_req: alloy_rpc_types_eth::TransactionRequest,
    ) -> Result<SeismicTransactionSigned, Self::Err> {
        let request = SeismicTransactionRequest {
            inner: tx_req,
            seismic_elements: None,
            /* Assumed that the transaction has already been decrypted in
             * the EthApiExt */
        };
        let Ok(tx) = request.build_typed_tx() else {
            return Err(SeismicEthApiError::Eth(EthApiError::TransactionConversionError));
        };

        // Create an empty signature for the transaction.
        let signature = Signature::new(Default::default(), Default::default(), false);
        Ok(SeismicTransactionSigned::new_unhashed(tx, signature))
    }
}

// Additional implementation for SeismicTransactionRequest directly
impl SimTxConverter<SeismicTransactionRequest, SeismicTransactionSigned> for SeismicSimTxConverter {
    type Err = SeismicEthApiError;

    fn convert_sim_tx(
        &self,
        request: SeismicTransactionRequest,
    ) -> Result<SeismicTransactionSigned, Self::Err> {
        let Ok(tx) = request.build_typed_tx() else {
            return Err(SeismicEthApiError::Eth(EthApiError::TransactionConversionError));
        };

        // Create an empty signature for the transaction.
        let signature = Signature::new(Default::default(), Default::default(), false);
        Ok(SeismicTransactionSigned::new_unhashed(tx, signature))
    }
}

// Implementation for SignableSeismicTransactionRequest wrapper
impl SimTxConverter<SignableSeismicTransactionRequest, SeismicTransactionSigned>
    for SeismicSimTxConverter
{
    type Err = SeismicEthApiError;

    fn convert_sim_tx(
        &self,
        request: SignableSeismicTransactionRequest,
    ) -> Result<SeismicTransactionSigned, Self::Err> {
        // Delegate to the inner SeismicTransactionRequest implementation
        self.convert_sim_tx(request.0)
    }
}

#[cfg(test)]
mod test {
    use alloy_primitives::{Bytes, FixedBytes};
    use reth_primitives_traits::SignedTransaction;
    use reth_rpc_eth_types::utils::recover_raw_transaction;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use std::str::FromStr;

    /// Helper function to generate a new raw seismic transaction for testing.
    /// Kept here for future use if the protocol changes and test data needs regeneration.
    ///
    /// Uses:
    /// - First Anvil private key:
    ///   0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    /// - Sender address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    /// - Network public key from seismic-enclave (insecure sample key)
    #[allow(dead_code)]
    fn generate_test_raw_tx() -> (Bytes, FixedBytes<32>) {
        use alloy_consensus::SignableTransaction;
        use alloy_eips::eip2718::Encodable2718;
        use alloy_primitives::{aliases::U96, hex, Address, TxKind, B256, U256};
        use k256::ecdsa::SigningKey;
        use secp256k1::PublicKey;
        use seismic_alloy_consensus::{TxSeismic, TxSeismicElements};
        use seismic_enclave::get_unsecure_sample_secp256k1_pk;

        // First anvil key
        let private_key_bytes: [u8; 32] =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap()
                .try_into()
                .unwrap();
        let signing_key = SigningKey::from_bytes(&private_key_bytes.into()).unwrap();

        // Network public key
        let network_pubkey: PublicKey = get_unsecure_sample_secp256k1_pk();

        // Create a seismic transaction
        let tx = TxSeismic {
            chain_id: 5123, // seismic dev chain id
            nonce: 1,
            gas_price: 20000000000,
            gas_limit: 210000,
            to: TxKind::Call(
                Address::from_str("0x3aB946eEC2553114040dE82D2e18798a51cf1e14").unwrap(),
            ),
            value: U256::from(1000000000000000u64),
            input: Bytes::from_str(
                "0x4e69e56c3bb999b8c98772ebb32aebcbd43b33e9e65a46333dfe6636f37f3009e93bad33",
            )
            .unwrap(),
            seismic_elements: TxSeismicElements {
                encryption_pubkey: network_pubkey,
                encryption_nonce: U96::from_str("0x7da3a99bf0f90d56551d99ea").unwrap(),
                message_version: 2,
                recent_block_hash: reth_seismic_chainspec::SEISMIC_DEV_GENESIS_HASH,
                expires_at_block: 1000000,
                signed_read: false,
            },
        };

        // Sign the transaction
        let sig_hash = tx.signature_hash();
        let sig = signing_key.sign_prehash_recoverable(&sig_hash.as_slice()).unwrap();
        let recoverid = sig.1;

        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(sig.0.r().to_bytes().as_ref()),
            U256::from_be_slice(sig.0.s().to_bytes().as_ref()),
            recoverid.is_y_odd(),
        );

        // Create signed transaction
        let signed: SeismicTransactionSigned =
            SignableTransaction::into_signed(tx, signature).into();

        // Encode to raw bytes
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);

        // Get hash
        let hash = *signed.tx_hash();

        (Bytes::from(encoded), hash)
    }

    #[test]
    fn test_recover_raw_tx() {
        let raw_tx = Bytes::from_str("0x4af8e9821403018504a817c80083033450943ab946eec2553114040de82d2e18798a51cf1e1487038d7ea4c68000a1028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a08c7da3a99bf0f90d56551d99ea02a01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef830f424080a44e69e56c3bb999b8c98772ebb32aebcbd43b33e9e65a46333dfe6636f37f3009e93bad3301a0da7f5d88daa3fc0581040d43c85cadc1b6f9d49122bea841fb52f7bcb66d5676a03537c25df47c46a53648a8d96203eb3eceb87d06186a071e35a4c6b2007bae1c").unwrap();
        let recovered = recover_raw_transaction::<SeismicTransactionSigned>(&raw_tx).unwrap();
        let expected = FixedBytes::<32>::from_str(
            "24e67060cf0788f8fbfe10a389f08cb071a76ff38a98c31c0803cf50fc8f2e29",
        )
        .unwrap();
        assert_eq!(recovered.tx_hash(), &expected);
    }
}
