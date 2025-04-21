//! Optimism block execution strategy.

use crate::{SeismicEvmConfig, SeismicReceiptBuilder};
use alloc::sync::Arc;
use reth_chainspec::ChainSpec;
use reth_evm::execute::BasicBlockExecutorProvider;

/// Helper type with backwards compatible methods to obtain executor providers.
#[derive(Debug)]
pub struct SeismicExecutorProvider;

impl SeismicExecutorProvider {
    /// Creates a new default seismic executor strategy factory.
    pub fn seismic(chain_spec: Arc<ChainSpec>) -> BasicBlockExecutorProvider<SeismicEvmConfig> {
        BasicBlockExecutorProvider::new(SeismicEvmConfig {
            executor_factory: EthBlockExecutorFactory::new(
                chain_spec,
                SeismicReceiptBuilder::default(),
            ),
            block_assembler: EthBlockAssembler::new(chain_spec),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainSpec;
    use alloy_consensus::{Block, BlockBody, Header, TxEip1559};
    use alloy_primitives::{
        b256, Address, PrimitiveSignature as Signature, StorageKey, StorageValue, U256,
    };
    use op_revm::constants::L1_BLOCK_CONTRACT;
    use reth_chainspec::{ChainSpecBuilder, MIN_TRANSACTION_GAS};
    use reth_evm::execute::{BasicBlockExecutorProvider, BlockExecutorProvider, Executor};
    use reth_primitives_traits::{Account, RecoveredBlock};
    use reth_revm::{database::StateProviderDatabase, test_utils::StateProviderTest};
    use reth_seismic_primitives::{SeismicReceipt, SeismicTransactionSigned};
    use revm::state::FlaggedStorage;
    use seismic_alloy_consensus::{SeismicTypedTransaction, TxDeposit};
    use std::{collections::HashMap, str::FromStr};

    fn create_op_state_provider() -> StateProviderTest {
        let mut db = StateProviderTest::default();

        let l1_block_contract_account =
            Account { balance: U256::ZERO, bytecode_hash: None, nonce: 1 };

        let mut l1_block_storage = HashMap::default();
        // base fee
        l1_block_storage
            .insert(StorageKey::with_last_byte(1), FlaggedStorage::new_from_value(1000000000));
        // l1 fee overhead
        l1_block_storage.insert(StorageKey::with_last_byte(5), FlaggedStorage::new_from_value(188));
        // l1 fee scalar
        l1_block_storage
            .insert(StorageKey::with_last_byte(6), FlaggedStorage::new_from_value(684000));
        // l1 free scalars post ecotone
        l1_block_storage.insert(
            StorageKey::with_last_byte(3),
            FlaggedStorage::new_from_value(
                StorageValue::from_str(
                    "0x0000000000000000000000000000000000001db0000d27300000000000000005",
                )
                .unwrap(),
            ),
        );

        db.insert_account(L1_BLOCK_CONTRACT, l1_block_contract_account, None, l1_block_storage);

        db
    }

    fn executor_provider(chain_spec: Arc<ChainSpec>) -> BasicBlockExecutorProvider<SeismicEvmConfig> {
        BasicBlockExecutorProvider::new(SeismicEvmConfig::new(
            chain_spec,
            SeismicReceiptBuilder::default(),
        ))
    }

    #[test]
    fn op_deposit_fields_pre_canyon() {
        let header = Header {
            timestamp: 1,
            number: 1,
            gas_limit: 1_000_000,
            gas_used: 42_000,
            receipts_root: b256!(
                "0x83465d1e7d01578c0d609be33570f91242f013e9e295b0879905346abbd63731"
            ),
            ..Default::default()
        };

        let mut db = create_op_state_provider();

        let addr = Address::ZERO;
        let account = Account { balance: U256::MAX, ..Account::default() };
        db.insert_account(addr, account, None, HashMap::default());

        let chain_spec = Arc::new(ChainSpecBuilder::base_mainnet().regolith_activated().build());

        let tx = SeismicTransactionSigned::new_unhashed(
            SeismicTypedTransaction::Eip1559(TxEip1559 {
                chain_id: chain_spec.chain.id(),
                nonce: 0,
                gas_limit: MIN_TRANSACTION_GAS,
                to: addr.into(),
                ..Default::default()
            }),
            Signature::test_signature(),
        );

        let tx_deposit = SeismicTransactionSigned::new_unhashed(
            SeismicTypedTransaction::Deposit(seismic_alloy_consensus::TxDeposit {
                from: addr,
                to: addr.into(),
                gas_limit: MIN_TRANSACTION_GAS,
                ..Default::default()
            }),
            Signature::test_signature(),
        );

        let provider = executor_provider(chain_spec);
        let mut executor = provider.executor(StateProviderDatabase::new(&db));

        // make sure the L1 block contract state is preloaded.
        executor.with_state_mut(|state| {
            state.load_cache_account(L1_BLOCK_CONTRACT).unwrap();
        });

        // Attempt to execute a block with one deposit and one non-deposit transaction
        let output = executor
            .execute(&RecoveredBlock::new_unhashed(
                Block {
                    header,
                    body: BlockBody { transactions: vec![tx, tx_deposit], ..Default::default() },
                },
                vec![addr, addr],
            ))
            .unwrap();

        let receipts = &output.receipts;
        let tx_receipt = &receipts[0];
        let deposit_receipt = &receipts[1];

        assert!(!matches!(tx_receipt, SeismicReceipt::Deposit(_)));
        // deposit_nonce is present only in deposit transactions
        let SeismicReceipt::Deposit(deposit_receipt) = deposit_receipt else {
            panic!("expected deposit")
        };
        assert!(deposit_receipt.deposit_nonce.is_some());
        // deposit_receipt_version is not present in pre canyon transactions
        assert!(deposit_receipt.deposit_receipt_version.is_none());
    }

    #[test]
    fn op_deposit_fields_post_canyon() {
        // ensure_create2_deployer will fail if timestamp is set to less than 2
        let header = Header {
            timestamp: 2,
            number: 1,
            gas_limit: 1_000_000,
            gas_used: 42_000,
            receipts_root: b256!(
                "0xfffc85c4004fd03c7bfbe5491fae98a7473126c099ac11e8286fd0013f15f908"
            ),
            ..Default::default()
        };

        let mut db = create_op_state_provider();
        let addr = Address::ZERO;
        let account = Account { balance: U256::MAX, ..Account::default() };

        db.insert_account(addr, account, None, HashMap::default());

        let chain_spec = Arc::new(ChainSpecBuilder::base_mainnet().canyon_activated().build());

        let tx = SeismicTransactionSigned::new_unhashed(
            SeismicTypedTransaction::Eip1559(TxEip1559 {
                chain_id: chain_spec.chain.id(),
                nonce: 0,
                gas_limit: MIN_TRANSACTION_GAS,
                to: addr.into(),
                ..Default::default()
            }),
            Signature::test_signature(),
        );

        let tx_deposit = SeismicTransactionSigned::new_unhashed(
            SeismicTypedTransaction::Deposit(seismic_alloy_consensus::TxDeposit {
                from: addr,
                to: addr.into(),
                gas_limit: MIN_TRANSACTION_GAS,
                ..Default::default()
            }),
            TxDeposit::signature(),
        );

        let provider = executor_provider(chain_spec);
        let mut executor = provider.executor(StateProviderDatabase::new(&db));

        // make sure the L1 block contract state is preloaded.
        executor.with_state_mut(|state| {
            state.load_cache_account(L1_BLOCK_CONTRACT).unwrap();
        });

        // attempt to execute an empty block with parent beacon block root, this should not fail
        let output = executor
            .execute(&RecoveredBlock::new_unhashed(
                Block {
                    header,
                    body: BlockBody { transactions: vec![tx, tx_deposit], ..Default::default() },
                },
                vec![addr, addr],
            ))
            .expect("Executing a block while canyon is active should not fail");

        let receipts = &output.receipts;
        let tx_receipt = &receipts[0];
        let deposit_receipt = &receipts[1];

        // deposit_receipt_version is set to 1 for post canyon deposit transactions
        assert!(!matches!(tx_receipt, SeismicReceipt::Deposit(_)));
        let SeismicReceipt::Deposit(deposit_receipt) = deposit_receipt else {
            panic!("expected deposit")
        };
        assert_eq!(deposit_receipt.deposit_receipt_version, Some(1));

        // deposit_nonce is present only in deposit transactions
        assert!(deposit_receipt.deposit_nonce.is_some());
    }
}
