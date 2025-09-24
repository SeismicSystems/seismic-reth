//! A basic Seismic payload builder implementation.

use alloy_network::eip2718::Typed2718;
use alloy_primitives::U256;
use alloy_rpc_types::TransactionTrait as _;
use futures::executor::block_on;
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthereumHardforks};
use reth_errors::{BlockExecutionError, BlockValidationError};
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_payload_builder::{BlobSidecars, EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_primitives_traits::SignedTransaction;
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_seismic_evm::SeismicEvmConfig;
use reth_seismic_primitives::{SeismicPrimitives, SeismicTransactionSigned};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::InvalidPoolTransactionError, identifier::TransactionId, BestTransactions,
    BestTransactionsAttributes, PoolTransaction, TransactionPool, ValidPoolTransaction,
};
use revm::context_interface::Block as _;
use seismic_alloy_consensus::SeismicTypedTransaction;
use seismic_enclave::EnclaveClientBuilder;
use std::path::Path;
use std::sync::Arc;
use std::{fs, time::Instant};
use tracing::{debug, trace, warn};

use reth_primitives_traits::transaction::error::InvalidTransactionError;

type BestTransactionsIter<Pool> = Box<
    dyn BestTransactions<Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>>,
>;

use crate::txn::{build_consume_gas_transaction, calculate_gas_distribution};

use super::SeismicBuilderConfig;

/// Disk-based transaction iterator for benchmarking
#[derive(Debug)]
pub struct DiskTransactionIterator<Transaction: PoolTransaction> {
    transactions: Vec<Arc<ValidPoolTransaction<Transaction>>>,
    current_index: usize,
}

impl<Transaction> DiskTransactionIterator<Transaction>
where
    Transaction: PoolTransaction<Consensus = SeismicTransactionSigned>,
{
    /// Creates a new iterator from transactions stored on disk
    pub fn new_from_disk<P: AsRef<Path>>(
        _file_path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // For now, we'll create 300 mock transactions
        // You can replace this with actual disk reading logic
        let transactions = Self::create_mock_transactions(300)?;

        Ok(Self { transactions, current_index: 0 })
    }

    /// Creates mock transactions for benchmarking
    /// Replace this with your actual transaction deserialization logic
    fn create_mock_transactions(
        count: usize,
    ) -> Result<Vec<Arc<ValidPoolTransaction<Transaction>>>, Box<dyn std::error::Error + Send + Sync>>
    {
        let target_gas: u64 = std::env::var("BENCHMARK_TARGET_GAS")
            .unwrap_or("140975".to_string())
            .parse()
            .expect("invalid BENCHMARK_TARGET_GAS");

        let std_dev: u64 = std::env::var("BENCHMARK_STD_DEV")
            .unwrap_or("49436".to_string())
            .parse()
            .expect("invalid BENCHMARK_STD_DEV");

        let txn_count: u64 = std::env::var("BENCHMARK_TXN_COUNT")
            .unwrap_or("300".to_string())
            .parse()
            .expect("invalid BENCHMARK_TXN_COUNT");

        tracing::error!("Txn count: {txn_count}");
        tracing::error!("std_dev: {std_dev}");
        tracing::error!("target_gas: {target_gas}");

        let mut txns = Vec::with_capacity(count);

        let gas_calcs = calculate_gas_distribution(target_gas, std_dev, txn_count);

        for gas in gas_calcs {
            let txn = block_on(build_consume_gas_transaction(gas)).unwrap();
            let raw_txn = SeismicTypedTransaction::Eip1559(
                txn.as_eip1559().unwrap().clone().into_parts().0.into(),
            );
            let seismic_txn =
                SeismicTransactionSigned::new(raw_txn, txn.signature().clone(), *txn.hash());

            let valid_pool_txn = ValidPoolTransaction {
                transaction: Transaction::try_from_consensus(
                    seismic_txn.try_into_recovered().unwrap(),
                )
                .unwrap_or_else(|_| panic!("Something went wrong")),
                transaction_id: TransactionId::new(0.into(), 0),
                propagate: false,
                timestamp: Instant::now(),
                origin: Default::default(),
                authority_ids: None,
            };

            txns.push(Arc::new(valid_pool_txn));
        }
        // This is a placeholder - you'll need to implement actual transaction loading
        // For now, we'll return an empty vector as we can't easily create mock ValidPoolTransactions
        // without the full transaction pool infrastructure
        debug!(target: "payload_builder", "Creating {} mock transactions for benchmarking", count);
        Ok(txns)
    }

    /// Creates an iterator with a fixed number of transactions for benchmarking
    pub fn with_count(count: usize) -> Self {
        debug!(target: "payload_builder", "Creating disk transaction iterator with {} transactions", count);
        Self { transactions: Vec::new(), current_index: 0 }
    }

    /// Load transactions from a JSON file
    pub fn load_from_json<P: AsRef<Path>>(
        file_path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let _contents = fs::read_to_string(file_path)?;
        // TODO: Deserialize transactions from JSON
        // This is where you'd implement the actual deserialization logic
        Ok(Self { transactions: Vec::new(), current_index: 0 })
    }
}

// First implement Iterator trait
impl<Transaction> Iterator for DiskTransactionIterator<Transaction>
where
    Transaction: PoolTransaction<Consensus = SeismicTransactionSigned>,
{
    type Item = Arc<ValidPoolTransaction<Transaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index < self.transactions.len() {
            let tx = self.transactions[self.current_index].clone();
            self.current_index += 1;
            Some(tx)
        } else {
            None
        }
    }
}

// Then implement BestTransactions trait
impl<Transaction> BestTransactions for DiskTransactionIterator<Transaction>
where
    Transaction: PoolTransaction<Consensus = SeismicTransactionSigned>,
{
    fn mark_invalid(&mut self, _tx: &Self::Item, _error: InvalidPoolTransactionError) {
        // For benchmarking, we might want to just log this or skip the transaction
        // In a real scenario, you'd handle marking transactions as invalid
        debug!("Transaction marked as invalid during benchmarking");
    }

    fn no_updates(&mut self) {
        // No-op for disk-based iterator since we're not listening to pool updates
    }

    fn set_skip_blobs(&mut self, _skip_blobs: bool) {
        // No-op for benchmarking - we can implement blob filtering later if needed
    }
}

/// Seismic payload builder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeismicPayloadBuilder<Pool, Client, EvmConfig = SeismicEvmConfig<EnclaveClientBuilder>> {
    /// Client providing access to node state.
    client: Client,
    /// Transaction pool.
    pool: Pool,
    /// The type responsible for creating the evm.
    evm_config: EvmConfig,
    /// Payload builder configuration.
    builder_config: SeismicBuilderConfig,
}

impl<Pool, Client, EvmConfig> SeismicPayloadBuilder<Pool, Client, EvmConfig> {
    /// [`SeismicPayloadBuilder`] constructor.
    pub const fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: SeismicBuilderConfig,
    ) -> Self {
        Self { client, pool, evm_config, builder_config }
    }
}

// Default implementation of [`PayloadBuilder`] for unit type
impl<Pool, Client, EvmConfig> PayloadBuilder for SeismicPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig:
        ConfigureEvm<Primitives = SeismicPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = SeismicTransactionSigned>>,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload<SeismicPrimitives>;

    fn try_build(
        &self,
        args: BuildArguments<EthPayloadBuilderAttributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<EthBuiltPayload<SeismicPrimitives>>, PayloadBuilderError> {
        default_seismic_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        if self.builder_config.await_payload_on_missing {
            MissingPayloadBehaviour::AwaitInProgress
        } else {
            MissingPayloadBehaviour::RaceEmptyPayload
        }
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let args = BuildArguments::new(Default::default(), config, Default::default(), None);

        default_seismic_payload(
            self.evm_config.clone(),
            self.client.clone(),
            self.pool.clone(),
            self.builder_config.clone(),
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Constructs an Seismic transaction payload using the best transactions from the pool.
///
/// Given build arguments including an Seismic client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
pub fn default_seismic_payload<EvmConfig, Client, Pool, F>(
    evm_config: EvmConfig,
    client: Client,
    pool: Pool,
    builder_config: SeismicBuilderConfig,
    args: BuildArguments<EthPayloadBuilderAttributes, EthBuiltPayload<SeismicPrimitives>>,
    best_txs: F,
) -> Result<BuildOutcome<EthBuiltPayload<SeismicPrimitives>>, PayloadBuilderError>
where
    EvmConfig:
        ConfigureEvm<Primitives = SeismicPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = SeismicTransactionSigned>>,
    F: FnOnce(BestTransactionsAttributes) -> BestTransactionsIter<Pool>,
{
    let BuildArguments { mut cached_reads, config, cancel, best_payload } = args;
    let PayloadConfig { parent_header, attributes } = config;

    let state_provider = client.state_by_block_hash(parent_header.hash())?;
    let state = StateProviderDatabase::new(&state_provider);
    let mut db =
        State::builder().with_database(cached_reads.as_db_mut(state)).with_bundle_update().build();

    let mut builder = evm_config
        .builder_for_next_block(
            &mut db,
            &parent_header,
            NextBlockEnvAttributes {
                timestamp: attributes.timestamp(),
                suggested_fee_recipient: attributes.suggested_fee_recipient(),
                prev_randao: attributes.prev_randao(),
                gas_limit: builder_config.gas_limit(parent_header.gas_limit),
                parent_beacon_block_root: attributes.parent_beacon_block_root(),
                withdrawals: Some(attributes.withdrawals().clone()),
            },
        )
        .map_err(PayloadBuilderError::other)?;

    let chain_spec = client.chain_spec();

    debug!(target: "payload_builder", id=%attributes.id, parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
    let mut cumulative_gas_used = 0;

    let benchmark_mode = std::env::var("BENCHMARK_MODE").is_ok();
    let block_gas_limit: u64 = builder.evm_mut().block().gas_limit;
    let base_fee = builder.evm_mut().block().basefee;
    let mut best_txs: Box<
        dyn BestTransactions<
            Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>,
        >,
    > = if benchmark_mode {
        debug!(target: "payload_builder", "BENCHMARK MODE: Using 300 disk transactions");
        match DiskTransactionIterator::new_from_disk("benchmark_transactions.json") {
            Ok(disk_iter) => Box::new(disk_iter),
            Err(e) => {
                warn!(target: "payload_builder", error = ?e, "Failed to load disk transactions, using empty iterator for benchmarking");
                Box::new(DiskTransactionIterator::with_count(300))
            }
        }
    } else {
        best_txs(BestTransactionsAttributes::new(
            base_fee,
            builder.evm_mut().block().blob_gasprice().map(|gasprice| gasprice as u64),
        ))
    };
    let mut total_fees = U256::ZERO;

    builder.apply_pre_execution_changes().map_err(|err| {
        warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
        PayloadBuilderError::Internal(err.into())
    })?;

    while let Some(pool_tx) = best_txs.next() {
        // ensure we still have capacity for this transaction
        if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
            // we can't fit this transaction into the block, so we need to mark it as invalid
            // which also removes all dependent transaction from the iterator before we can
            // continue
            best_txs.mark_invalid(
                &pool_tx,
                InvalidPoolTransactionError::ExceedsGasLimit(pool_tx.gas_limit(), block_gas_limit),
            );
            continue;
        }

        // check if the job was cancelled, if so we can exit early
        if cancel.is_cancelled() {
            return Ok(BuildOutcome::Cancelled);
        }

        // convert tx to a signed transaction
        let tx = pool_tx.to_consensus();
        debug!("default_seismic_payload: tx: {:?}", tx);

        let gas_used = match builder.execute_transaction(tx.clone()) {
            Ok(gas_used) => gas_used,
            Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                error, ..
            })) => {
                if error.is_nonce_too_low() {
                    // if the nonce is too low, we can skip this transaction
                    trace!(target: "payload_builder", %error, ?tx, "skipping nonce too low transaction");
                } else {
                    // if the transaction is invalid, we can skip it and all of its
                    // descendants
                    debug!(target: "payload_builder", %error, ?tx, "skipping invalid transaction and its descendants");
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::Consensus(
                            InvalidTransactionError::TxTypeNotSupported,
                        ),
                    );
                }
                continue;
            }
            // this is an error that we should treat as fatal for this attempt
            Err(err) => return Err(PayloadBuilderError::evm(err)),
        };

        // update add to total fees
        let miner_fee =
            tx.effective_tip_per_gas(base_fee).expect("fee is always valid; execution succeeded");
        total_fees += U256::from(miner_fee) * U256::from(gas_used);
        cumulative_gas_used += gas_used;
    }

    // check if we have a better block
    if !is_better_payload(best_payload.as_ref(), total_fees) {
        // Release db
        drop(builder);
        // can skip building the block
        return Ok(BuildOutcome::Aborted { fees: total_fees, cached_reads });
    }

    let BlockBuilderOutcome { execution_result, block, .. } = builder.finish(&state_provider)?;

    let requests = chain_spec
        .is_prague_active_at_timestamp(attributes.timestamp)
        .then_some(execution_result.requests);

    // initialize empty blob sidecars at first. If cancun is active then this will
    let mut blob_sidecars = Vec::new();

    // only determine cancun fields when active
    if chain_spec.is_cancun_active_at_timestamp(attributes.timestamp) {
        // grab the blob sidecars from the executed txs
        blob_sidecars = pool
            .get_all_blobs_exact(
                block
                    .body()
                    .transactions()
                    .filter(|tx| tx.is_eip4844())
                    .map(|tx| *tx.tx_hash())
                    .collect(),
            )
            .map_err(PayloadBuilderError::other)?;
    }

    let mut sidecars = BlobSidecars::Empty;
    blob_sidecars
        .into_iter()
        .map(Arc::unwrap_or_clone)
        .for_each(|s| sidecars.push_sidecar_variant(s));

    let sealed_block = Arc::new(block.sealed_block().clone());
    debug!(target: "payload_builder", id=%attributes.id, sealed_block_header = ?sealed_block.sealed_header(), "sealed built block");

    let payload = EthBuiltPayload::<SeismicPrimitives>::new_seismic_payload(
        attributes.id,
        sealed_block,
        total_fees,
        sidecars,
        requests,
    );

    Ok(BuildOutcome::Better { payload, cached_reads })
}

#[test]
fn test() {}
