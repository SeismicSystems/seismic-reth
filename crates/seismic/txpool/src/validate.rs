//! Validator for Seismic transactions.
//! It is a [`TransactionValidator`] implementation that validates seismic transaction.

use std::sync::Arc;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_primitives_traits::{Block, SealedBlock};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_transaction_pool::{EthPoolTransaction, TransactionOrigin};
use reth_transaction_pool::validate::{EthTransactionValidatorInner, TransactionValidationOutcome, TransactionValidator};


/// Validator Seismic transactions.
/// It is a [`TransactionValidator`] implementation that validates seismic transaction.
#[derive(Debug, Clone)]
pub struct SeismicTransactionValidator<Client, T> {
    /// The type that performs the actual validation.
    inner: Arc<EthTransactionValidatorInner<Client, T>>,
}

impl<Client, Tx> SeismicTransactionValidator<Client, Tx> {
    /// Returns the configured chain spec
    pub fn chain_spec(&self) -> Arc<Client::ChainSpec>
    where
        Client: ChainSpecProvider,
    {
        self.client().chain_spec()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        &self.inner.client
    }
}

impl<Client, Tx> SeismicTransactionValidator<Client, Tx>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + StateProviderFactory,
    Tx: EthPoolTransaction, // TODO: use seismic pool transaction
{
    /// Validates a single transaction.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    pub fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> TransactionValidationOutcome<Tx> {
        self.inner.validate_one(origin, transaction)
    }

    /// Validates a single transaction with the provided state provider.
    ///
    /// This allows reusing the same provider across multiple transaction validations,
    /// which can improve performance when validating many transactions.
    ///
    /// If `state` is `None`, a new state provider will be created.
    pub fn validate_one_with_state(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        state: &mut Option<Box<dyn StateProvider>>,
    ) -> TransactionValidationOutcome<Tx> {
        self.inner.validate_one_with_provider(origin, transaction, state)
    }

    /// Validates all given transactions.
    ///
    /// Returns all outcomes for the given transactions in the same order.
    ///
    /// See also [`Self::validate_one`]
    pub fn validate_all(
        &self,
        transactions: Vec<(TransactionOrigin, Tx)>,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        self.inner.validate_batch(transactions)
    }

    /// Validates all given transactions with origin.
    ///
    /// Returns all outcomes for the given transactions in the same order.
    ///
    /// See also [`Self::validate_one`]
    pub fn validate_all_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Tx> + Send,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        self.inner.validate_batch_with_origin(origin, transactions)
    }
}

impl<Client, Tx> TransactionValidator for SeismicTransactionValidator<Client, Tx>
where
    Client: ChainSpecProvider<ChainSpec: EthereumHardforks> + StateProviderFactory,
    Tx: EthPoolTransaction,
{
    type Transaction = Tx;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        self.validate_one(origin, transaction)
    }

    async fn validate_transactions(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        self.validate_all(transactions)
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        self.validate_all_with_origin(origin, transactions)
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block.header())
    }
}
