use super::SeismicNodeCore;
use crate::SeismicEthApi;
use alloy_consensus::transaction::Either;
use alloy_eips::eip7702::{RecoveredAuthorization, SignedAuthorization};
use alloy_primitives::{TxKind, U256};
use alloy_rpc_types_eth::transaction::TransactionRequest;
use reth_evm::{execute::BlockExecutorFactory, ConfigureEvm, EvmEnv, EvmFactory, SpecFor};
use reth_node_api::NodePrimitives;
use reth_rpc_eth_api::{
    helpers::{estimate::EstimateCall, Call, EthCall, LoadBlock, LoadState, SpawnBlocking},
    FromEthApiError, FromEvmError, FullEthApiTypes, IntoEthApiError,
};
use reth_rpc_eth_types::{revm_utils::CallFees, EthApiError, RpcInvalidTransactionError};
use reth_storage_api::{ProviderHeader, ProviderTx};
use revm::{context::TxEnv, context_interface::Block, Database};
use seismic_alloy_consensus::SeismicTxType;
use seismic_revm::{transaction::abstraction::RngMode, SeismicTransaction};
use tracing::debug;

impl<N> EthCall for SeismicEthApi<N>
where
    Self: EstimateCall + LoadBlock + FullEthApiTypes,
    N: SeismicNodeCore,
{
}

impl<N> EstimateCall for SeismicEthApi<N>
where
    Self: Call,
    Self::Error: From<EthApiError>,
    N: SeismicNodeCore,
{
}

impl<N> Call for SeismicEthApi<N>
where
    Self: LoadState<
            Evm: ConfigureEvm<
                Primitives: NodePrimitives<
                    BlockHeader = ProviderHeader<Self::Provider>,
                    SignedTx = ProviderTx<Self::Provider>,
                >,
                BlockExecutorFactory: BlockExecutorFactory<
                    EvmFactory: EvmFactory<Tx = seismic_revm::SeismicTransaction<TxEnv>>,
                >,
            >,
            Error: FromEvmError<Self::Evm>,
        > + SpawnBlocking,
    Self::Error: From<EthApiError>,
    N: SeismicNodeCore,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    fn create_txn_env(
        &self,
        evm_env: &EvmEnv<SpecFor<Self::Evm>>,
        request: TransactionRequest,
        mut db: impl Database<Error: Into<EthApiError>>,
    ) -> Result<SeismicTransaction<TxEnv>, Self::Error> {
        // Ensure that if versioned hashes are set, they're not empty
        if request.blob_versioned_hashes.as_ref().is_some_and(|hashes| hashes.is_empty()) {
            return Err(RpcInvalidTransactionError::BlobTransactionMissingBlobHashes.into_eth_err())
        }

        let tx_type = if request.authorization_list.is_some() {
            SeismicTxType::Eip7702
        } else if request.max_fee_per_gas.is_some() || request.max_priority_fee_per_gas.is_some() {
            SeismicTxType::Eip1559
        } else if request.access_list.is_some() {
            SeismicTxType::Eip2930
        } else {
            SeismicTxType::Seismic
        } as u8;

        let TransactionRequest {
            from,
            to,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas,
            value,
            input,
            nonce,
            access_list,
            chain_id,
            blob_versioned_hashes,
            max_fee_per_blob_gas,
            authorization_list,
            transaction_type: _,
            sidecar: _,
        } = request;

        let CallFees { max_priority_fee_per_gas, gas_price, max_fee_per_blob_gas } =
            CallFees::ensure_fees(
                gas_price.map(U256::from),
                max_fee_per_gas.map(U256::from),
                max_priority_fee_per_gas.map(U256::from),
                U256::from(evm_env.block_env.basefee),
                blob_versioned_hashes.as_deref(),
                max_fee_per_blob_gas.map(U256::from),
                evm_env.block_env.blob_gasprice().map(U256::from),
            )?;

        let gas_limit = gas.unwrap_or(
            // Use maximum allowed gas limit. The reason for this
            // is that both Erigon and Geth use pre-configured gas cap even if
            // it's possible to derive the gas limit from the block:
            // <https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/cmd/rpcdaemon/commands/trace_adhoc.go#L956
            // https://github.com/ledgerwatch/erigon/blob/eae2d9a79cb70dbe30b3a6b79c436872e4605458/eth/ethconfig/config.go#L94>
            evm_env.block_env.gas_limit,
        );

        let chain_id = chain_id.unwrap_or(evm_env.cfg_env.chain_id);

        let caller = from.unwrap_or_default();

        let nonce = if let Some(nonce) = nonce {
            nonce
        } else {
            db.basic(caller).map_err(Into::into)?.map(|acc| acc.nonce).unwrap_or_default()
        };

        let authorization_list: Vec<Either<SignedAuthorization, RecoveredAuthorization>> =
            authorization_list
                .unwrap_or_default()
                .iter()
                .map(|auth| Either::Left(auth.clone()))
                .collect();
        let env = TxEnv {
            tx_type,
            gas_limit,
            nonce,
            caller,
            gas_price: gas_price.saturating_to(),
            gas_priority_fee: max_priority_fee_per_gas.map(|v| v.saturating_to()),
            kind: to.unwrap_or(TxKind::Create),
            value: value.unwrap_or_default(),
            data: input
                .try_into_unique_input()
                .map_err(Self::Error::from_eth_err)?
                .unwrap_or_default(),
            chain_id: Some(chain_id),
            access_list: access_list.unwrap_or_default(),
            // EIP-4844 fields
            blob_hashes: blob_versioned_hashes.unwrap_or_default(),
            max_fee_per_blob_gas: max_fee_per_blob_gas
                .map(|v| v.saturating_to())
                .unwrap_or_default(),
            // EIP-7702 fields
            authorization_list,
        };

        debug!("reth-seismic-rpc::eth create_txn_env {:?}", env);

        Ok(SeismicTransaction {
            base: env,
            tx_hash: Default::default(),
            rng_mode: RngMode::Simulation,
        })
    }
}
