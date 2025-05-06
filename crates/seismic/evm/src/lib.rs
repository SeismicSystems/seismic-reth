//! EVM config for vanilla optimism.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/SeismicSystems/seismic-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{borrow::Cow, sync::Arc};
use alloy_consensus::{BlockHeader, Header};
use alloy_eips::eip1559::INITIAL_BASE_FEE;
use alloy_evm::{eth::EthBlockExecutionCtx, EvmFactory, FromRecoveredTx};
use alloy_primitives::{Bytes, U256};
use build::SeismicBlockAssembler;
use core::fmt::Debug;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_ethereum_forks::EthereumHardfork;
use reth_evm::{
    eth::EthBlockExecutorFactory, ConfigureEvm, EvmEnv, NextBlockEnvAttributes, TransactionEnv,
};
use reth_primitives_traits::{NodePrimitives, SealedBlock, SealedHeader, SignedTransaction};
use reth_seismic_primitives::{SeismicBlock, SeismicPrimitives, SeismicTransactionSigned};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::block::BlobExcessGasAndPrice,
    primitives::hardfork::SpecId,
};
use seismic_revm::SeismicSpecId;
use std::convert::Infallible;

mod execute;
pub use execute::*;
mod receipts;
pub use receipts::*;
mod build;

pub use alloy_seismic_evm::{SeismicEvmFactory, SeismicEvm};

/// Ethereum-related EVM configuration.
#[derive(Debug, Clone)]
pub struct SeismicEvmConfig<EvmFactory = SeismicEvmFactory> {
    /// Inner [`EthBlockExecutorFactory`].
    pub executor_factory:
        EthBlockExecutorFactory<SeismicRethReceiptBuilder, Arc<ChainSpec>, EvmFactory>,
    /// Ethereum block assembler.
    pub block_assembler: SeismicBlockAssembler<ChainSpec>,
}

impl SeismicEvmConfig {
    /// Creates a new Ethereum EVM configuration with the given chain spec and EVM factory.
    pub fn seismic(chain_spec: Arc<ChainSpec>) -> Self {
        SeismicEvmConfig::new_with_evm_factory(chain_spec, SeismicEvmFactory::default())
    }
}

impl<EvmFactory> SeismicEvmConfig<EvmFactory> {
    /// Creates a new Ethereum EVM configuration with the given chain spec and EVM factory.
    pub fn new_with_evm_factory(chain_spec: Arc<ChainSpec>, evm_factory: EvmFactory) -> Self {
        Self {
            block_assembler: SeismicBlockAssembler::new(chain_spec.clone()),
            executor_factory: EthBlockExecutorFactory::new(
                SeismicRethReceiptBuilder::default(),
                chain_spec,
                evm_factory,
            ),
        }
    }

    /// Returns the chain spec associated with this configuration.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.executor_factory.spec()
    }

    /// Sets the extra data for the block assembler.
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.block_assembler.extra_data = extra_data;
        self
    }
}

impl<EvmF> ConfigureEvm for SeismicEvmConfig<EvmF>
where
    EvmF: EvmFactory<Tx: TransactionEnv + FromRecoveredTx<SeismicTransactionSigned>, Spec = SpecId>
        + Clone
        + Debug
        + Send
        + Sync
        + Unpin
        + 'static,
{
    type Primitives = SeismicPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory =
        EthBlockExecutorFactory<SeismicRethReceiptBuilder, Arc<ChainSpec>, EvmF>;
    type BlockAssembler = SeismicBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<SpecId> {
        // TODO: use the correct spec id
        let spec = SpecId::LATEST;

        // configure evm env based on parent block
        let cfg_env = CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec);

        let block_env = BlockEnv {
            number: header.number(),
            beneficiary: header.beneficiary(),
            timestamp: header.timestamp(),
            difficulty: U256::ZERO,
            prevrandao: header.mix_hash(),
            gas_limit: header.gas_limit(),
            basefee: header.base_fee_per_gas().unwrap_or_default(),
            // EIP-4844 excess blob gas of this block, introduced in Cancun
            blob_excess_gas_and_price: header
                .excess_blob_gas
                .map(|excess_blob_gas| BlobExcessGasAndPrice::new(excess_blob_gas, true)),
        };

        EvmEnv { cfg_env, block_env }
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        // ensure we're not missing any timestamp based hardforks
        let spec_id = revm_spec_by_timestamp_and_block_number(
            self.chain_spec(),
            attributes.timestamp,
            parent.number() + 1,
        );

        // configure evm env based on parent block
        let cfg = CfgEnv::new().with_chain_id(self.chain_spec().chain().id()).with_spec(spec_id);

        // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // cancun now, we need to set the excess blob gas to the default value(0)
        let blob_excess_gas_and_price = parent
            .maybe_next_block_excess_blob_gas(
                self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
            )
            .or_else(|| (spec_id == SpecId::CANCUN).then_some(0))
            .map(|gas| BlobExcessGasAndPrice::new(gas, spec_id >= SpecId::PRAGUE));

        let mut basefee = parent.next_block_base_fee(
            self.chain_spec().base_fee_params_at_timestamp(attributes.timestamp),
        );

        let mut gas_limit = attributes.gas_limit;

        // If we are on the London fork boundary, we need to multiply the parent's gas limit by the
        // elasticity multiplier to get the new gas limit.
        if self.chain_spec().fork(EthereumHardfork::London).transitions_at_block(parent.number + 1)
        {
            let elasticity_multiplier = self
                .chain_spec()
                .base_fee_params_at_timestamp(attributes.timestamp)
                .elasticity_multiplier;

            // multiply the gas limit by the elasticity multiplier
            gas_limit *= elasticity_multiplier as u64;

            // set the base fee to the initial base fee from the EIP-1559 spec
            basefee = Some(INITIAL_BASE_FEE)
        }

        let block_env = BlockEnv {
            number: parent.number + 1,
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: attributes.timestamp,
            difficulty: U256::ZERO,
            prevrandao: Some(attributes.prev_randao),
            gas_limit,
            // calculate basefee based on parent block's gas usage
            basefee: basefee.unwrap_or_default(),
            // calculate excess gas based on parent block's blob gas usage
            blob_excess_gas_and_price,
        };

        Ok((cfg, block_env).into())
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<SeismicBlock>,
    ) -> EthBlockExecutionCtx<'a> {
        EthBlockExecutionCtx {
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx<'_> {
        EthBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(Cow::Owned),
        }
    }
}

/// Code copied and pasted from reth-evm-ethereum
/// Map the latest active hardfork at the given timestamp or block number to a revm [`SpecId`].
pub fn revm_spec_by_timestamp_and_block_number(
    chain_spec: &ChainSpec,
    timestamp: u64,
    block_number: u64,
) -> SpecId {
    if chain_spec
        .fork(EthereumHardfork::Osaka)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::OSAKA
    } else if chain_spec
        .fork(EthereumHardfork::Prague)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::PRAGUE
    } else if chain_spec
        .fork(EthereumHardfork::Cancun)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::CANCUN
    } else if chain_spec
        .fork(EthereumHardfork::Shanghai)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::SHANGHAI
    } else if chain_spec.is_paris_active_at_block(block_number) {
        SpecId::MERGE
    } else if chain_spec
        .fork(EthereumHardfork::London)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::LONDON
    } else if chain_spec
        .fork(EthereumHardfork::Berlin)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::BERLIN
    } else if chain_spec
        .fork(EthereumHardfork::Istanbul)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::ISTANBUL
    } else if chain_spec
        .fork(EthereumHardfork::Petersburg)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::PETERSBURG
    } else if chain_spec
        .fork(EthereumHardfork::Byzantium)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::BYZANTIUM
    } else if chain_spec
        .fork(EthereumHardfork::SpuriousDragon)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::SPURIOUS_DRAGON
    } else if chain_spec
        .fork(EthereumHardfork::Tangerine)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::TANGERINE
    } else if chain_spec
        .fork(EthereumHardfork::Homestead)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::HOMESTEAD
    } else if chain_spec
        .fork(EthereumHardfork::Frontier)
        .active_at_timestamp_or_number(timestamp, block_number)
    {
        SpecId::FRONTIER
    } else {
        panic!(
            "invalid hardfork chainspec: expected at least one hardfork, got {:?}",
            chain_spec.hardforks
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, Receipt};
    use alloy_eips::eip7685::Requests;
    use alloy_genesis::Genesis;
    use alloy_primitives::{bytes, map::HashMap, Address, LogData, B256};
    use op_revm::OpSpecId;
    use reth_chainspec::{ChainSpec, BASE_MAINNET};
    use reth_evm::execute::ProviderError;
    use reth_execution_types::{
        AccountRevertInit, BundleStateInit, Chain, ExecutionOutcome, RevertsInit,
    };
    use reth_primitives_traits::{Account, RecoveredBlock};
    use reth_seismic_primitives::{SeismicBlock, SeismicPrimitives, SeismicReceipt};
    use revm::{
        database::{BundleState, CacheDB},
        database_interface::EmptyDBTyped,
        inspector::NoOpInspector,
        primitives::Log,
        state::AccountInfo,
    };
    use std::sync::Arc;

    fn test_evm_config() -> SeismicEvmConfig {
        SeismicEvmConfig::optimism(BASE_MAINNET.clone())
    }

    #[test]
    fn test_fill_cfg_and_block_env() {
        // Create a default header
        let header = Header::default();

        // Build the ChainSpec for Ethereum mainnet, activating London, Paris, and Shanghai
        // hardforks
        let chain_spec = ChainSpec::builder()
            .chain(0.into())
            .genesis(Genesis::default())
            .london_activated()
            .paris_activated()
            .shanghai_activated()
            .build();

        // Use the `SeismicEvmConfig` to create the `cfg_env` and `block_env` based on the
        // ChainSpec, Header, and total difficulty
        let EvmEnv { cfg_env, .. } =
            SeismicEvmConfig::seismic(Arc::new(chain_spec.clone())).evm_env(&header);

        // Assert that the chain ID in the `cfg_env` is correctly set to the chain ID of the
        // ChainSpec
        assert_eq!(cfg_env.chain_id, chain_spec.chain().id());
    }

    #[test]
    fn test_evm_with_env_default_spec() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv::default();

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        // Check that the EVM environment
        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_custom_cfg() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create a custom configuration environment with a chain ID of 111
        let cfg = CfgEnv::new().with_chain_id(111).with_spec(OpSpecId::default());

        let evm_env = EvmEnv { cfg_env: cfg.clone(), ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env);

        // Check that the EVM environment is initialized with the custom environment
        assert_eq!(evm.cfg, cfg);
    }

    #[test]
    fn test_evm_with_env_custom_block_and_tx() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create customs block and tx env
        let block =
            BlockEnv { basefee: 1000, gas_limit: 10_000_000, number: 42, ..Default::default() };

        let evm_env = EvmEnv { block_env: block, ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        // Verify that the block and transaction environments are set correctly
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn test_evm_with_spec_id() {
        let evm_config = test_evm_config();

        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env =
            EvmEnv { cfg_env: CfgEnv::new().with_spec(OpSpecId::ECOTONE), ..Default::default() };

        let evm = evm_config.evm_with_env(db, evm_env.clone());

        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_and_default_inspector() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env = EvmEnv { cfg_env: Default::default(), ..Default::default() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the EVM environment is set to default values
        assert_eq!(evm.block, evm_env.block_env);
        assert_eq!(evm.cfg, evm_env.cfg_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_custom_cfg() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let cfg = CfgEnv::new().with_chain_id(111).with_spec(OpSpecId::default());
        let block = BlockEnv::default();
        let evm_env = EvmEnv { block_env: block, cfg_env: cfg.clone() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the EVM environment is set with custom configuration
        assert_eq!(evm.cfg, cfg);
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_custom_block_tx() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        // Create custom block and tx environment
        let block =
            BlockEnv { basefee: 1000, gas_limit: 10_000_000, number: 42, ..Default::default() };
        let evm_env = EvmEnv { block_env: block, ..Default::default() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Verify that the block and transaction environments are set correctly
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn test_evm_with_env_inspector_and_spec_id() {
        let evm_config = test_evm_config();
        let db = CacheDB::<EmptyDBTyped<ProviderError>>::default();

        let evm_env =
            EvmEnv { cfg_env: CfgEnv::new().with_spec(OpSpecId::ECOTONE), ..Default::default() };

        let evm = evm_config.evm_with_env_and_inspector(db, evm_env.clone(), NoOpInspector {});

        // Check that the spec ID is set properly
        assert_eq!(evm.cfg, evm_env.cfg_env);
        assert_eq!(evm.block, evm_env.block_env);
    }

    #[test]
    fn receipts_by_block_hash() {
        // Create a default recovered block
        let block: RecoveredBlock<SeismicBlock> = Default::default();

        // Define block hashes for block1 and block2
        let block1_hash = B256::new([0x01; 32]);
        let block2_hash = B256::new([0x02; 32]);

        // Clone the default block into block1 and block2
        let mut block1 = block.clone();
        let mut block2 = block;

        // Set the hashes of block1 and block2
        block1.set_block_number(10);
        block1.set_hash(block1_hash);

        block2.set_block_number(11);
        block2.set_hash(block2_hash);

        // Create a random receipt object, receipt1
        let receipt1 = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create another random receipt object, receipt2
        let receipt2 = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 1325345,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![receipt1.clone()], vec![receipt2]];

        // Create an ExecutionOutcome object with the created bundle, receipts, an empty requests
        // vector, and first_block set to 10
        let execution_outcome = ExecutionOutcome::<SeismicReceipt> {
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block: 10,
        };

        // Create a Chain object with a BTreeMap of blocks mapped to their block numbers,
        // including block1_hash and block2_hash, and the execution_outcome
        let chain: Chain<SeismicPrimitives> =
            Chain::new([block1, block2], execution_outcome.clone(), None);

        // Assert that the proper receipt vector is returned for block1_hash
        assert_eq!(chain.receipts_by_block_hash(block1_hash), Some(vec![&receipt1]));

        // Create an ExecutionOutcome object with a single receipt vector containing receipt1
        let execution_outcome1 = ExecutionOutcome {
            bundle: Default::default(),
            receipts: vec![vec![receipt1]],
            requests: vec![],
            first_block: 10,
        };

        // Assert that the execution outcome at the first block contains only the first receipt
        assert_eq!(chain.execution_outcome_at_block(10), Some(execution_outcome1));

        // Assert that the execution outcome at the tip block contains the whole execution outcome
        assert_eq!(chain.execution_outcome_at_block(11), Some(execution_outcome));
    }

    #[test]
    fn test_initialisation() {
        // Create a new BundleState object with initial data
        let bundle = BundleState::new(
            vec![(Address::new([2; 20]), None, Some(AccountInfo::default()), HashMap::default())],
            vec![vec![(Address::new([2; 20]), None, vec![])]],
            vec![],
        );

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        }))]];

        // Create a Requests object with a vector of requests
        let requests = vec![Requests::new(vec![bytes!("dead"), bytes!("beef"), bytes!("beebee")])];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: bundle.clone(),
            receipts: receipts.clone(),
            requests: requests.clone(),
            first_block,
        };

        // Assert that creating a new ExecutionOutcome using the constructor matches exec_res
        assert_eq!(
            ExecutionOutcome::new(bundle, receipts.clone(), first_block, requests.clone()),
            exec_res
        );

        // Create a BundleStateInit object and insert initial data
        let mut state_init: BundleStateInit = HashMap::default();
        state_init
            .insert(Address::new([2; 20]), (None, Some(Account::default()), HashMap::default()));

        // Create a HashMap for account reverts and insert initial data
        let mut revert_inner: HashMap<Address, AccountRevertInit> = HashMap::default();
        revert_inner.insert(Address::new([2; 20]), (None, vec![]));

        // Create a RevertsInit object and insert the revert_inner data
        let mut revert_init: RevertsInit = HashMap::default();
        revert_init.insert(123, revert_inner);

        // Assert that creating a new ExecutionOutcome using the new_init method matches
        // exec_res
        assert_eq!(
            ExecutionOutcome::new_init(
                state_init,
                revert_init,
                vec![],
                receipts,
                first_block,
                requests,
            ),
            exec_res
        );
    }

    #[test]
    fn test_block_number_to_index() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        }))]];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block,
        };

        // Test before the first block
        assert_eq!(exec_res.block_number_to_index(12), None);

        // Test after after the first block but index larger than receipts length
        assert_eq!(exec_res.block_number_to_index(133), None);

        // Test after the first block
        assert_eq!(exec_res.block_number_to_index(123), Some(0));
    }

    #[test]
    fn test_get_logs() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![Log::<LogData>::default()],
            status: true.into(),
        })]];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block,
        };

        // Get logs for block number 123
        let logs: Vec<&Log> = exec_res.logs(123).unwrap().collect();

        // Assert that the logs match the expected logs
        assert_eq!(logs, vec![&Log::<LogData>::default()]);
    }

    #[test]
    fn test_receipts_by_block() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![Log::<LogData>::default()],
            status: true.into(),
        }))]];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(), // Default value for bundle
            receipts,                   // Include the created receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Get receipts for block number 123 and convert the result into a vector
        let receipts_by_block: Vec<_> = exec_res.receipts_by_block(123).iter().collect();

        // Assert that the receipts for block number 123 match the expected receipts
        assert_eq!(
            receipts_by_block,
            vec![&Some(SeismicReceipt::Legacy(Receipt {
                cumulative_gas_used: 46913,
                logs: vec![Log::<LogData>::default()],
                status: true.into(),
            }))]
        );
    }

    #[test]
    fn test_receipts_len() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![Log::<LogData>::default()],
            status: true.into(),
        }))]];

        // Create an empty Receipts object
        let receipts_empty = vec![];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            bundle: Default::default(), // Default value for bundle
            receipts,                   // Include the created receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Assert that the length of receipts in exec_res is 1
        assert_eq!(exec_res.len(), 1);

        // Assert that exec_res is not empty
        assert!(!exec_res.is_empty());

        // Create a ExecutionOutcome object with an empty Receipts object
        let exec_res_empty_receipts: ExecutionOutcome<SeismicReceipt> = ExecutionOutcome {
            bundle: Default::default(), // Default value for bundle
            receipts: receipts_empty,   // Include the empty receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Assert that the length of receipts in exec_res_empty_receipts is 0
        assert_eq!(exec_res_empty_receipts.len(), 0);

        // Assert that exec_res_empty_receipts is empty
        assert!(exec_res_empty_receipts.is_empty());
    }

    #[test]
    fn test_revert_to() {
        // Create a random receipt object
        let receipt = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![vec![Some(receipt.clone())], vec![Some(receipt.clone())]];

        // Define the first block number
        let first_block = 123;

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests =
            vec![Requests::new(vec![request.clone()]), Requests::new(vec![request.clone()])];

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let mut exec_res =
            ExecutionOutcome { bundle: Default::default(), receipts, requests, first_block };

        // Assert that the revert_to method returns true when reverting to the initial block number.
        assert!(exec_res.revert_to(123));

        // Assert that the receipts are properly cut after reverting to the initial block number.
        assert_eq!(exec_res.receipts, vec![vec![Some(receipt)]]);

        // Assert that the requests are properly cut after reverting to the initial block number.
        assert_eq!(exec_res.requests, vec![Requests::new(vec![request])]);

        // Assert that the revert_to method returns false when attempting to revert to a block
        // number greater than the initial block number.
        assert!(!exec_res.revert_to(133));

        // Assert that the revert_to method returns false when attempting to revert to a block
        // number less than the initial block number.
        assert!(!exec_res.revert_to(10));
    }

    #[test]
    fn test_extend_execution_outcome() {
        // Create a Receipt object with specific attributes.
        let receipt = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object containing the receipt.
        let receipts = vec![vec![Some(receipt.clone())]];

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests = vec![Requests::new(vec![request.clone()])];

        // Define the initial block number.
        let first_block = 123;

        // Create an ExecutionOutcome object.
        let mut exec_res =
            ExecutionOutcome { bundle: Default::default(), receipts, requests, first_block };

        // Extend the ExecutionOutcome object by itself.
        exec_res.extend(exec_res.clone());

        // Assert the extended ExecutionOutcome matches the expected outcome.
        assert_eq!(
            exec_res,
            ExecutionOutcome {
                bundle: Default::default(),
                receipts: vec![vec![Some(receipt.clone())], vec![Some(receipt)]],
                requests: vec![Requests::new(vec![request.clone()]), Requests::new(vec![request])],
                first_block: 123,
            }
        );
    }

    #[test]
    fn test_split_at_execution_outcome() {
        // Create a random receipt object
        let receipt = SeismicReceipt::Legacy(Receipt {
            cumulative_gas_used: 46913,
            logs: vec![],
            status: true.into(),
        });

        // Create a Receipts object with a vector of receipt vectors
        let receipts = vec![
            vec![Some(receipt.clone())],
            vec![Some(receipt.clone())],
            vec![Some(receipt.clone())],
        ];

        // Define the first block number
        let first_block = 123;

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests = vec![
            Requests::new(vec![request.clone()]),
            Requests::new(vec![request.clone()]),
            Requests::new(vec![request.clone()]),
        ];

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res =
            ExecutionOutcome { bundle: Default::default(), receipts, requests, first_block };

        // Split the ExecutionOutcome at block number 124
        let result = exec_res.clone().split_at(124);

        // Define the expected lower ExecutionOutcome after splitting
        let lower_execution_outcome = ExecutionOutcome {
            bundle: Default::default(),
            receipts: vec![vec![Some(receipt.clone())]],
            requests: vec![Requests::new(vec![request.clone()])],
            first_block,
        };

        // Define the expected higher ExecutionOutcome after splitting
        let higher_execution_outcome = ExecutionOutcome {
            bundle: Default::default(),
            receipts: vec![vec![Some(receipt.clone())], vec![Some(receipt)]],
            requests: vec![Requests::new(vec![request.clone()]), Requests::new(vec![request])],
            first_block: 124,
        };

        // Assert that the split result matches the expected lower and higher outcomes
        assert_eq!(result.0, Some(lower_execution_outcome));
        assert_eq!(result.1, higher_execution_outcome);

        // Assert that splitting at the first block number returns None for the lower outcome
        assert_eq!(exec_res.clone().split_at(123), (None, exec_res));
    }
}
