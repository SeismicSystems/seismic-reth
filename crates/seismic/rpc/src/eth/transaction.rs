//! Loads and formats Seismic transaction RPC response.

use super::ext::SeismicTransaction;
use crate::{
    eth::{SeismicNodeCore, SignableSeismicTransactionRequest},
    utils::recover_typed_data_request,
    SeismicEthApi, SeismicEthApiError,
};
use alloy_consensus::{transaction::Recovered, Transaction as _};
use alloy_primitives::{Address, Bytes, Signature, B256};
use alloy_rpc_types_eth::{Transaction, TransactionInfo};
use alloy_sol_types::SolCall;
use reth_primitives_traits::SignedTransaction;
use reth_rpc_convert::transaction::{RpcTxConverter, SimTxConverter};
use reth_rpc_eth_api::{
    helpers::{spec::SignersForRpc, EthTransactions, LoadTransaction},
    FromEthApiError, RpcConvert, RpcNodeCore,
};
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError};
use reth_rpc_layer::{
    OpsWhitelistTxAuth, Whitelist, OPS_AUTH_CONTRACT, OPS_AUTH_SLOT, WHITELIST_TX_SENTINEL,
};
use reth_seismic_primitives::SeismicTransactionSigned;
use reth_storage_api::{BlockReader, BlockReaderIdExt, ProviderTx, StateProviderFactory};
use reth_transaction_pool::{
    AddedTransactionOutcome, PoolTransaction, TransactionOrigin, TransactionPool,
};
use seismic_alloy_consensus::{Decodable712, SeismicTxEnvelope, TypedDataRequest};
use seismic_alloy_rpc_types::SeismicTransactionRequest;
use std::time::{SystemTime, UNIX_EPOCH};

enum SentinelAction {
    Whitelist { target: Address, expires_at: u64 },
    Revoke { target: Address },
}

impl<N, Rpc> SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
    fn try_handle_sentinel_transaction<T>(
        &self,
        recovered: &Recovered<T>,
        whitelist: &Whitelist,
    ) -> Result<bool, SeismicEthApiError>
    where
        T: alloy_consensus::Transaction,
    {
        let Some(action) = parse_sentinel_action(recovered)? else { return Ok(false) };

        let governance_address = self.ops_governance_address()?;
        if recovered.signer() != governance_address {
            return Err(rpc_error("unauthorized ops whitelist sentinel signer"));
        }

        match action {
            SentinelAction::Whitelist { target, expires_at } => {
                if expires_at <= current_unix_timestamp() {
                    return Err(rpc_error("ops whitelist expiry must be in the future"));
                }
                whitelist.add(target, expires_at);
            }
            SentinelAction::Revoke { target } => {
                whitelist.remove(&target);
            }
        }

        Ok(true)
    }

    fn ops_governance_address(&self) -> Result<Address, SeismicEthApiError> {
        let state = self.provider().latest().map_err(SeismicEthApiError::from)?;
        let value = state
            .storage(OPS_AUTH_CONTRACT, OPS_AUTH_SLOT)
            .map_err(SeismicEthApiError::from)?
            .ok_or_else(|| rpc_error("ops governance slot is unset"))?;
        let bytes = value.value.to_be_bytes::<32>();
        let address = Address::from_slice(&bytes[12..]);
        if address.is_zero() {
            return Err(rpc_error("ops governance address resolved to zero address"));
        }
        Ok(address)
    }
}

impl<N, Rpc> EthTransactions for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
    fn signers(&self) -> &SignersForRpc<Self::Provider, Self::NetworkTypes> {
        self.inner.signers()
    }

    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        let recovered: Recovered<
            <<Self::Pool as TransactionPool>::Transaction as PoolTransaction>::Pooled,
        > = recover_raw_transaction(&tx)?;
        tracing::debug!(target: "reth-seismic-rpc::eth", tx_hash = %recovered.tx_hash(), "serving seismic_eth_api::send_raw_transaction");

        if let Some(whitelist) = self.ops_whitelist.as_ref() {
            if self.try_handle_sentinel_transaction(&recovered, whitelist)? {
                return Ok(B256::from(*recovered.tx_hash()))
            }
        }

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
    N: SeismicNodeCore<Provider: BlockReader<Transaction = ProviderTx<Self::Provider>>>,
    <<<Self as RpcNodeCore>::Pool as TransactionPool>::Transaction as PoolTransaction>::Pooled:
        Decodable712,
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

fn parse_sentinel_action<T>(
    recovered: &Recovered<T>,
) -> Result<Option<SentinelAction>, SeismicEthApiError>
where
    T: alloy_consensus::Transaction,
{
    if recovered.to() != Some(WHITELIST_TX_SENTINEL) {
        return Ok(None)
    }

    let input = recovered.input();
    let selector = input
        .get(..4)
        .ok_or_else(|| rpc_error("ops whitelist sentinel calldata is missing selector"))?;

    if selector == OpsWhitelistTxAuth::whitelistKeyCall::SELECTOR {
        let call = OpsWhitelistTxAuth::whitelistKeyCall::abi_decode(input)
            .map_err(|_| rpc_error("failed to decode ops whitelist calldata"))?;
        return Ok(Some(SentinelAction::Whitelist {
            target: call.target,
            expires_at: call.expiresAt,
        }))
    }

    if selector == OpsWhitelistTxAuth::revokeKeyCall::SELECTOR {
        let call = OpsWhitelistTxAuth::revokeKeyCall::abi_decode(input)
            .map_err(|_| rpc_error("failed to decode ops revoke calldata"))?;
        return Ok(Some(SentinelAction::Revoke { target: call.target }))
    }

    Err(rpc_error("unknown ops whitelist sentinel selector"))
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before unix epoch").as_secs()
}

fn rpc_error(message: &'static str) -> SeismicEthApiError {
    SeismicEthApiError::Eth(EthApiError::Other(Box::new(jsonrpsee_types::ErrorObject::owned(
        -32000, message, None::<()>,
    ))))
}

/// Seismic RPC transaction converter that implements Debug
#[derive(Clone, Debug)]
pub struct SeismicRpcTxConverter;

impl Default for SeismicRpcTxConverter {
    fn default() -> Self {
        Self::new()
    }
}

impl SeismicRpcTxConverter {
    /// Creates a new converter
    pub const fn new() -> Self {
        Self
    }
}

/// Seismic simulation transaction converter that implements Debug
#[derive(Clone, Debug)]
pub struct SeismicSimTxConverter;

impl Default for SeismicSimTxConverter {
    fn default() -> Self {
        Self::new()
    }
}

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
#[allow(clippy::unwrap_used)]
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
        use alloy_primitives::{aliases::U96, hex, Address, TxKind, U256};
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
            authorization_list: vec![],
        };

        // Sign the transaction
        let sig_hash = tx.signature_hash();
        let sig = signing_key.sign_prehash_recoverable(sig_hash.as_slice()).unwrap();
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
    fn test_generate_and_recover_raw_tx() {
        let (raw_bytes, hash) = generate_test_raw_tx();
        let recovered = recover_raw_transaction::<SeismicTransactionSigned>(&raw_bytes).unwrap();
        assert_eq!(recovered.tx_hash(), &hash);
    }
}
