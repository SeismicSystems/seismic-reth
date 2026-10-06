//! Seismic transaction validator

use crate::{
    payment::{maximum_gas_cost, ProviderRegistryStorage},
    recent_block_cache::RecentBlockCache,
    SeismicPaymentError,
};
use alloy_consensus::BlockHeader;
use alloy_primitives::Sealable;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::{transaction::error::InvalidTransactionError, Block};
use reth_provider::{AccountInfoReader, BlockReaderIdExt, StateProvider, StateProviderFactory};
use reth_seismic_primitives::{transaction::error::SeismicTxError, SeismicTransactionSigned};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError,
    validate::{TransactionValidationOutcome, TransactionValidator},
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin,
};
use seismic_alloy_consensus::{SeismicTxType, SeismicTypedTransaction, TxSeismicElements};
use seismic_revm::gas_token_registry::{
    aggregate_balance, select_payment, GasPayment, RegistryError,
};
use std::{
    fmt,
    marker::PhantomData,
    sync::{Arc, RwLock},
};

/// Seismic transaction validator that adds seismic-specific validation on top of Ethereum
/// validation.
pub struct SeismicTransactionValidator<Client, T> {
    /// Inner Ethereum transaction validator
    inner: Arc<EthTransactionValidator<Client, T>>,
    /// Cache of recent block hashes for O(1) validation
    recent_blocks: RwLock<RecentBlockCache>,
    /// Purpose keyring, read for its rotation schedule only (`pending()`): while a
    /// key rotation is pending, transactions whose expiry crosses the activation
    /// boundary are rejected (`docs/design/purpose-key-rotation.md` §6). The pool
    /// never touches key material. `None` disables the rule.
    keyring: Option<Arc<reth_seismic_keys::PurposeKeyring>>,
    /// Phantom data for transaction type
    _pd: PhantomData<T>,
}

impl<Client, T> fmt::Debug for SeismicTransactionValidator<Client, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeismicTransactionValidator")
            .field("inner", &"EthTransactionValidator")
            .field("recent_blocks", &"RwLock<RecentBlockCache>")
            .finish()
    }
}

impl<Client, T> SeismicTransactionValidator<Client, T>
where
    Client: BlockReaderIdExt,
{
    /// Creates a new seismic transaction validator wrapping an Ethereum validator.
    ///
    /// Pre-populates the recent block hash cache from the client so that validation
    /// works immediately without a cold-start fallback.
    pub fn new(inner: EthTransactionValidator<Client, T>) -> Self {
        // Seismic execution ignores access lists, including their intrinsic gas.
        // Configure this here so every Seismic validator uses the same policy,
        // while standalone Ethereum validators retain EIP-2930 charging.
        let inner = inner.with_access_list_gas_charging(false);
        let mut cache = RecentBlockCache::default();

        // Populate cache from the current canonical chain
        if let Ok(tip) = inner.client().best_block_number() {
            cache.rebuild_to_tip(tip, |n| {
                inner.client().header_by_number(n).ok()?.map(|h| h.hash_slow())
            });
        }

        Self {
            inner: Arc::new(inner),
            recent_blocks: RwLock::new(cache),
            keyring: None,
            _pd: PhantomData,
        }
    }

    /// Enables the key-rotation boundary rule, reading the pending rotation from
    /// `keyring`'s schedule.
    pub fn with_keyring(mut self, keyring: Arc<reth_seismic_keys::PurposeKeyring>) -> Self {
        self.keyring = Some(keyring);
        self
    }

    /// Get a reference to the inner validator
    pub fn inner(&self) -> &EthTransactionValidator<Client, T> {
        &self.inner
    }
}

impl<Client, Tx> TransactionValidator for SeismicTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory
        + BlockReaderIdExt
        + ChainSpecProvider<ChainSpec: reth_chainspec::EthereumHardforks>
        + Clone
        + 'static,
    Tx: EthPoolTransaction<Consensus = SeismicTransactionSigned> + fmt::Debug,
{
    type Transaction = Tx;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        // One provider snapshot supplies both Ethereum account/code validation
        // and registry/token checks. Never call latest() again after validation.
        let state = match self.inner.client().latest() {
            Ok(state) => Arc::<dyn StateProvider>::from(state),
            Err(error) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error))
            }
        };
        self.validate_with_state(origin, transaction, state)
    }

    fn on_new_head_block<B>(&self, new_tip_block: &reth_primitives_traits::SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block);

        let mut cache = self.recent_blocks.write().unwrap_or_else(|e| e.into_inner());
        cache.update(new_tip_block.hash(), new_tip_block.header().number(), |n| {
            self.inner.client().header_by_number(n).ok()?.map(|h| h.hash_slow())
        });
    }
}

impl<Client, Tx> SeismicTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory
        + BlockReaderIdExt
        + ChainSpecProvider<ChainSpec: reth_chainspec::EthereumHardforks>,
    Tx: EthPoolTransaction<Consensus = SeismicTransactionSigned> + fmt::Debug,
{
    /// Share the provider through the existing Ethereum validator extension point.
    fn validate_with_state(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        state: Arc<dyn StateProvider>,
    ) -> TransactionValidationOutcome<Tx> {
        let mut account_state: Option<Box<dyn AccountInfoReader>> = Some(Box::new(state.clone()));
        let outcome = self.inner.validate_one_with_state(origin, transaction, &mut account_state);

        // If the standard validation failed, return early
        match outcome {
            TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                transaction: valid_tx,
                propagate,
                bytecode_hash,
                authorities,
            } => {
                // Validation passed, continue with seismic-specific checks
                let consensus_tx = valid_tx.transaction().clone_into_consensus();

                // Only validate seismic transactions
                if consensus_tx.tx_type() == SeismicTxType::Seismic {
                    // Get seismic elements from the transaction
                    if let seismic_alloy_consensus::SeismicTypedTransaction::Seismic(seismic_tx) =
                        consensus_tx.transaction()
                    {
                        let seismic_elements = &seismic_tx.seismic_elements;

                        // Freshness check, shared with the eviction task. `is_complete()` gates the
                        // recent_block_hash check so a transient cache hole can't reject a valid
                        // tx.
                        let freshness = {
                            let cache =
                                self.recent_blocks.read().unwrap_or_else(|e| e.into_inner());
                            seismic_freshness_error(seismic_elements, &cache, cache.is_complete())
                        };
                        if let Some(err) = freshness {
                            return TransactionValidationOutcome::Invalid(
                                valid_tx.into_transaction(),
                                InvalidTransactionError::SeismicTx(err.to_string()).into(),
                            );
                        }

                        // Key-rotation boundary rule: with a rotation pending, admit
                        // only transactions that expire before its activation, so the
                        // existing expiry eviction drains all old-key transactions
                        // exactly at the boundary.
                        if let Some(keyring) = &self.keyring {
                            if let Some(err) = rotation_boundary_error(
                                seismic_elements.expires_at_block,
                                keyring.pending(),
                            ) {
                                return TransactionValidationOutcome::Invalid(
                                    valid_tx.into_transaction(),
                                    InvalidTransactionError::SeismicTx(err.to_string()).into(),
                                );
                            }
                        }
                    }
                }

                let selector = match consensus_tx.transaction() {
                    SeismicTypedTransaction::Seismic(tx) => match tx.gas_payment {
                        seismic_alloy_consensus::GasPayment::Auto => GasPayment::Auto,
                        seismic_alloy_consensus::GasPayment::Native => GasPayment::Native,
                        seismic_alloy_consensus::GasPayment::Token(token) => {
                            GasPayment::Token(token)
                        }
                    },
                    _ => GasPayment::Auto,
                };
                let sender = *valid_tx.transaction().sender_ref();
                let value = valid_tx.transaction().value();
                let gas_cost = match maximum_gas_cost(valid_tx.transaction()) {
                    Ok(cost) => cost,
                    Err(error) => {
                        return TransactionValidationOutcome::Invalid(
                            valid_tx.into_transaction(),
                            InvalidPoolTransactionError::other(SeismicPaymentError(error)),
                        )
                    }
                };
                let mut reader = ProviderRegistryStorage(state.as_ref());
                // Admission always reserves the original signed value. It cannot
                // assume failed decryption will waive value funding at execution.
                let selected =
                    select_payment(&mut reader, selector, sender, balance, value, gas_cost);
                if let Err(error) = selected {
                    return match error {
                        RegistryError::Storage(error) => {
                            TransactionValidationOutcome::Error(*valid_tx.hash(), Box::new(error))
                        }
                        RegistryError::Transaction(error) => TransactionValidationOutcome::Invalid(
                            valid_tx.into_transaction(),
                            InvalidPoolTransactionError::other(SeismicPaymentError(error)),
                        ),
                    }
                }

                // This full scan is intentionally separate from exact lazy selection.
                // Mixed-selector nonce sequences need one sender-wide approximate
                // scalar, not just the selected asset. No sum authorizes one fee.
                let aggregate = match aggregate_balance(&mut reader, sender, balance) {
                    Ok(balance) => balance,
                    Err(RegistryError::Storage(error)) => {
                        return TransactionValidationOutcome::Error(
                            *valid_tx.hash(),
                            Box::new(error),
                        )
                    }
                    Err(RegistryError::Transaction(error)) => {
                        return TransactionValidationOutcome::Invalid(
                            valid_tx.into_transaction(),
                            InvalidPoolTransactionError::other(SeismicPaymentError(error)),
                        )
                    }
                };

                TransactionValidationOutcome::Valid {
                    balance: aggregate,
                    state_nonce,
                    transaction: valid_tx,
                    propagate,
                    bytecode_hash,
                    authorities,
                }
            }
            // For invalid or error outcomes, pass through
            other => other,
        }
    }
}

/// Freshness violation for `elements`, or `None` if fresh (`recent_block_hash` in window, not
/// expired). Shared by ingress and the eviction task. `check_recent_hash` gates the hash check so a
/// transient cache hole isn't read as staleness; expiry always applies.
pub(crate) fn seismic_freshness_error(
    elements: &TxSeismicElements,
    cache: &RecentBlockCache,
    check_recent_hash: bool,
) -> Option<SeismicTxError> {
    if check_recent_hash && !cache.contains(&elements.recent_block_hash) {
        return Some(SeismicTxError::RecentBlockHashNotFound {
            hash: elements.recent_block_hash,
            lookback: crate::SEISMIC_TX_RECENT_BLOCK_LOOKBACK,
        });
    }

    let current_block = cache.current_block_number();
    if current_block > elements.expires_at_block {
        return Some(SeismicTxError::TransactionExpired {
            current_block,
            expires_at_block: elements.expires_at_block,
        });
    }

    None
}

/// Key-rotation boundary violation, or `None` when no rotation is pending or the
/// expiry stays below the pending activation block
/// (`docs/design/purpose-key-rotation.md` §6).
///
/// Admitted transactions therefore always satisfy `expires_at_block < activation`,
/// so the freshness eviction drains every old-key transaction from the pool exactly
/// at the boundary — an honest builder can never include a transaction encrypted to
/// the outgoing key at or after activation.
pub(crate) fn rotation_boundary_error(
    expires_at_block: u64,
    pending_rotation: Option<(u64, u64)>,
) -> Option<SeismicTxError> {
    let (_, activation_block) = pending_rotation?;
    (expires_at_block >= activation_block)
        .then_some(SeismicTxError::ExpiryCrossesRotation { expires_at_block, activation_block })
}

#[cfg(test)]
#[path = "validator/payment_tests.rs"]
mod payment_tests;

#[cfg(test)]
#[allow(clippy::panic)] // Test code - panic on failure is acceptable
mod tests {
    use super::*;
    use crate::SeismicPooledTransaction;
    use alloy_consensus::{transaction::Recovered, SignableTransaction, TxEip2930, TxLegacy};
    use alloy_eips::{
        eip2718::Encodable2718,
        eip2930::{AccessList, AccessListItem},
    };
    use alloy_primitives::{Address, Bytes, FlaggedStorage, Signature, TxKind, B256, U256};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, error::InvalidPoolTransactionError,
        validate::EthTransactionValidatorBuilder, PoolTransaction, TransactionOrigin,
    };
    use revm::{
        context::{result::InvalidTransaction, TxEnv},
        handler::validation::validate_initial_tx_gas,
        primitives::hardfork::SpecId,
    };
    use seismic_revm::gas_token_registry::{
        balance_storage_key, token_metadata_slot, GAS_TOKEN_REGISTRY, TOKEN_COUNT_SLOT,
    };

    const GAS_LIMIT: u64 = 100_000;
    const GAS_PRICE: u128 = 10_000_000_000; // 10 gwei
    /// Maximum gas cost of the test transaction: `GAS_LIMIT * GAS_PRICE` = 10^15 wei.
    const GAS_COST: u128 = GAS_LIMIT as u128 * GAS_PRICE;
    /// Raw 6-decimal USDC amount that scales to exactly [`GAS_COST`] (scaling is 10^12).
    const USDC_RAW_GAS_COST: u128 = GAS_COST / 1_000_000_000_000;
    const ONE_ETH: u128 = 1_000_000_000_000_000_000;

    fn sender() -> Address {
        Address::with_last_byte(0x42)
    }

    /// Validates a legacy transfer of `value` against a mock state where the
    /// sender holds `native` wei and `usdc_raw` 6-decimal USDC units.
    ///
    /// Uses a legacy (non-Seismic-type) transaction so the affordability check
    /// is exercised without needing a recent-block-hash cache entry.
    async fn validate_with(
        native: U256,
        usdc_raw: U256,
        value: U256,
    ) -> TransactionValidationOutcome<SeismicPooledTransaction> {
        let sender = sender();
        let client = MockEthProvider::default().with_chain_spec(SEISMIC_MAINNET.clone());
        client.add_account(sender, ExtendedAccount::new(0, native));
        let token = Address::with_last_byte(0x44);
        let root = U256::from(3);
        let metadata = U256::from_be_slice(token.as_slice()) |
            (U256::from(1) << 160usize) | // active
            (U256::from(1) << 168usize) | // Public
            (U256::from(6) << 176usize);
        client.add_account(
            GAS_TOKEN_REGISTRY,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (
                    TOKEN_COUNT_SLOT.to_be_bytes::<32>().into(),
                    FlaggedStorage::public(U256::from(1)),
                ),
                (
                    token_metadata_slot(0).to_be_bytes::<32>().into(),
                    FlaggedStorage::public(metadata),
                ),
                (
                    (token_metadata_slot(0) + U256::from(1)).to_be_bytes::<32>().into(),
                    FlaggedStorage::public(root),
                ),
            ]),
        );
        client.add_account(
            token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                balance_storage_key(sender, root).to_be_bytes::<32>().into(),
                FlaggedStorage::public(usdc_raw),
            )]),
        );

        // Mirror the production pool wiring: the inner Ethereum validator runs
        // with its native balance check disabled, making the seismic validator
        // the sole affordability gate.
        let eth_validator = EthTransactionValidatorBuilder::new(client)
            .no_shanghai()
            .no_cancun()
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        let validator = SeismicTransactionValidator::new(eth_validator);

        let tx = TxLegacy {
            chain_id: Some(5123),
            nonce: 0,
            gas_price: GAS_PRICE,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(Address::with_last_byte(0x43)),
            value,
            input: Bytes::new(),
        };
        // The validator never recovers the signer (it trusts `Recovered`), so a
        // dummy signature is sufficient.
        let signature = Signature::new(U256::from(1), U256::from(1), false);
        let signed: SeismicTransactionSigned =
            SignableTransaction::into_signed(tx, signature).into();
        let recovered = Recovered::new_unchecked(signed, sender);
        let encoded_length = recovered.encode_2718_len();
        let pooled = SeismicPooledTransaction::new(recovered, encoded_length);

        validator.validate_transaction(TransactionOrigin::External, pooled).await
    }

    /// Compare execution and pool admission at access-list gas boundaries.
    /// Seismic ignores access lists for both intrinsic gas and warming.
    async fn assert_access_list_intrinsic_gas_parity(
        access_list: AccessList,
        gas_limit: u64,
        expected_intrinsic_gas: u64,
    ) {
        let sender = sender();
        let tx = TxEip2930 {
            chain_id: 5123,
            gas_limit,
            gas_price: GAS_PRICE,
            to: TxKind::Call(Address::with_last_byte(0x43)),
            access_list,
            ..Default::default()
        };
        let execution_tx = TxEnv {
            tx_type: 1,
            caller: sender,
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
            kind: tx.to,
            value: tx.value,
            data: tx.input.clone(),
            nonce: tx.nonce,
            chain_id: Some(tx.chain_id),
            access_list: tx.access_list.clone(),
            ..Default::default()
        };
        let should_accept = gas_limit >= expected_intrinsic_gas;
        let execution = validate_initial_tx_gas(&execution_tx, SpecId::MERCURY);
        match execution {
            Ok(gas) => {
                assert!(should_accept, "execution must reject an insufficient gas limit");
                assert_eq!(gas.initial_gas, expected_intrinsic_gas);
            }
            Err(InvalidTransaction::CallGasCostMoreThanGasLimit { initial_gas, .. }) => {
                assert!(!should_accept, "execution must accept a sufficient gas limit");
                assert_eq!(initial_gas, expected_intrinsic_gas);
            }
            other => panic!("unexpected execution gas result: {other:?}"),
        }

        let client = MockEthProvider::default().with_chain_spec(SEISMIC_MAINNET.clone());
        client.add_account(sender, ExtendedAccount::new(0, U256::from(ONE_ETH)));
        let eth_validator = EthTransactionValidatorBuilder::new(client)
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        // As in the affordability tests, recovery is outside this validator.
        let signature = Signature::new(U256::from(1), U256::from(1), false);
        let signed: SeismicTransactionSigned = tx.into_signed(signature).into();
        let recovered = Recovered::new_unchecked(signed, sender);
        let encoded_length = recovered.encode_2718_len();
        let pooled: SeismicPooledTransaction =
            SeismicPooledTransaction::new(recovered, encoded_length);
        // At these limits, Ethereum accepts only the empty-list 21,000-gas control.
        let eth_outcome =
            eth_validator.validate_transaction(TransactionOrigin::External, pooled.clone()).await;
        if execution_tx.access_list.is_empty() && should_accept {
            assert!(matches!(eth_outcome, TransactionValidationOutcome::Valid { .. }));
        } else {
            assert!(matches!(
                eth_outcome,
                TransactionValidationOutcome::Invalid(
                    _,
                    InvalidPoolTransactionError::IntrinsicGasTooLow
                )
            ));
        }

        let original = pooled.clone_into_consensus();
        let validator = SeismicTransactionValidator::new(eth_validator);
        let outcome = validator.validate_transaction(TransactionOrigin::External, pooled).await;
        match outcome {
            TransactionValidationOutcome::Valid { transaction, .. } => {
                assert!(should_accept, "pool must reject an insufficient gas limit");
                assert_eq!(transaction.transaction().clone_into_consensus(), original);
            }
            TransactionValidationOutcome::Invalid(
                _,
                InvalidPoolTransactionError::IntrinsicGasTooLow,
            ) => assert!(!should_accept, "pool must accept a sufficient gas limit"),
            other => panic!("unexpected pool outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn access_list_intrinsic_gas_parity_empty_list() {
        for gas_limit in [20_999, 21_000] {
            assert_access_list_intrinsic_gas_parity(AccessList::default(), gas_limit, 21_000).await;
        }
    }

    #[tokio::test]
    async fn access_list_intrinsic_gas_parity_nonempty_list() {
        let access_list = AccessList(vec![AccessListItem {
            address: Address::with_last_byte(0x43),
            storage_keys: vec![B256::ZERO],
        }]);
        for gas_limit in [20_999, 21_000] {
            assert_access_list_intrinsic_gas_parity(access_list.clone(), gas_limit, 21_000).await;
        }
    }

    /// Asserts the outcome is an `InsufficientFunds` rejection and returns the
    /// reported `(got, expected)` balances.
    fn expect_insufficient_funds(
        outcome: TransactionValidationOutcome<SeismicPooledTransaction>,
    ) -> (U256, U256) {
        match outcome {
            TransactionValidationOutcome::Invalid(_, error) => match error
                .downcast_other_ref::<SeismicPaymentError>()
                .map(SeismicPaymentError::reason)
            {
                Some(InvalidTransaction::LackOfFundForMaxFee { fee, balance }) => {
                    (**balance, **fee)
                }
                other => panic!("expected typed insufficient-funds reason, got: {other:?}"),
            },
            other => panic!("expected InsufficientFunds rejection, got: {other:?}"),
        }
    }

    /// Native covers the value exactly and USDC covers gas exactly. Neither
    /// balance alone covers gas + value, but component-wise the tx is payable.
    #[tokio::test]
    async fn accepts_when_native_covers_value_and_usdc_covers_gas() {
        let outcome =
            validate_with(U256::from(ONE_ETH), U256::from(USDC_RAW_GAS_COST), U256::from(ONE_ETH))
                .await;
        match outcome {
            TransactionValidationOutcome::Valid { balance, .. } => {
                // pool-tracked scalar is native + usdc_scaled (a sound upper bound
                // on cost; see the `Valid` arm in the validator)
                assert_eq!(balance, U256::from(ONE_ETH) + U256::from(GAS_COST));
            }
            other => panic!("expected Valid outcome, got: {other:?}"),
        }
    }

    /// USDC alone covers gas + value, but the value transfer can only be paid
    /// in native token: the tx could never execute and must be rejected.
    #[tokio::test]
    async fn rejects_when_usdc_covers_cost_but_native_below_value() {
        let native = U256::from(ONE_ETH - 1);
        // 2 ETH worth of USDC (raw 6-decimal units), well above gas + value
        let usdc_raw = U256::from(2 * ONE_ETH / 1_000_000_000_000);
        let outcome = validate_with(native, usdc_raw, U256::from(ONE_ETH)).await;
        let (got, expected) = expect_insufficient_funds(outcome);
        assert_eq!(got, native);
        // USDC covers gas, so the native balance only needs to cover the value
        assert_eq!(expected, U256::from(ONE_ETH));
    }

    /// Native alone covers gas + value with no USDC at all.
    #[tokio::test]
    async fn accepts_when_native_covers_cost_without_usdc() {
        let outcome = validate_with(U256::from(2 * ONE_ETH), U256::ZERO, U256::from(ONE_ETH)).await;
        assert!(
            matches!(outcome, TransactionValidationOutcome::Valid { .. }),
            "expected Valid outcome, got: {outcome:?}"
        );
    }

    /// Native covers the value but nothing more, and USDC is one raw unit short
    /// of the gas cost: unaffordable in every combination.
    #[tokio::test]
    async fn rejects_when_neither_balance_sufficient() {
        let native = U256::from(ONE_ETH);
        let usdc_raw = U256::from(USDC_RAW_GAS_COST - 1);
        let outcome = validate_with(native, usdc_raw, U256::from(ONE_ETH)).await;
        let (got, expected) = expect_insufficient_funds(outcome);
        assert_eq!(got, native);
        // USDC cannot cover gas, so native would need to cover gas + value
        assert_eq!(expected, U256::from(ONE_ETH + GAS_COST));
    }

    /// The common USDC-gas case: no native balance, no value transfer, USDC
    /// covering exactly the gas cost.
    #[tokio::test]
    async fn accepts_usdc_gas_only_with_zero_native() {
        let outcome = validate_with(U256::ZERO, U256::from(USDC_RAW_GAS_COST), U256::ZERO).await;
        assert!(
            matches!(outcome, TransactionValidationOutcome::Valid { .. }),
            "expected Valid outcome, got: {outcome:?}"
        );
    }

    /// No pending rotation (the state of every network today): the boundary rule
    /// never fires, whatever the expiry.
    #[test]
    fn boundary_rule_is_inert_without_a_pending_rotation() {
        assert_eq!(rotation_boundary_error(u64::MAX, None), None);
        assert_eq!(rotation_boundary_error(0, None), None);
    }

    /// With a rotation pending at activation block A, expiries below A pass and
    /// expiries at or beyond A are rejected — admitted transactions always expire
    /// before the boundary.
    #[test]
    fn boundary_rule_caps_expiry_below_activation() {
        let pending = Some((1, 100));
        assert_eq!(rotation_boundary_error(99, pending), None);
        assert_eq!(
            rotation_boundary_error(100, pending),
            Some(SeismicTxError::ExpiryCrossesRotation {
                expires_at_block: 100,
                activation_block: 100
            })
        );
        assert_eq!(
            rotation_boundary_error(u64::MAX, pending),
            Some(SeismicTxError::ExpiryCrossesRotation {
                expires_at_block: u64::MAX,
                activation_block: 100
            })
        );
    }
}
