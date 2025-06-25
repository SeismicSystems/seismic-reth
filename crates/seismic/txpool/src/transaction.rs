use alloy_consensus::{
    transaction::Recovered, BlobTransactionSidecar, BlobTransactionValidationError, Typed2718,
};
use alloy_eips::{eip2930::AccessList, eip7702::SignedAuthorization, Encodable2718};
use alloy_primitives::{Address, Bytes, TxHash, TxKind, B256, U256};
use c_kzg::KzgSettings;
use core::fmt::Debug;
use reth_primitives_traits::{InMemorySize, SignedTransaction};
use reth_seismic_primitives::SeismicTransactionSigned;
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};
use seismic_alloy_consensus::SeismicTxEnvelope;
use std::sync::Arc;

/// Pool Transaction for Seismic.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct SeismicPooledTransaction<Cons = SeismicTransactionSigned, Pooled = SeismicTxEnvelope> {
    #[deref]
    inner: EthPooledTransaction<Cons>,
    /// The pooled transaction type.
    _pd: core::marker::PhantomData<Pooled>,
}

impl<Cons: SignedTransaction, Pooled> SeismicPooledTransaction<Cons, Pooled> {
    /// Create a new [`SeismicPooledTransaction`].
    pub fn new(transaction: Recovered<Cons>, encoded_length: usize) -> Self {
        Self {
            inner: EthPooledTransaction::new(transaction, encoded_length),
            _pd: core::marker::PhantomData,
        }
    }
}

impl<Cons, Pooled> PoolTransaction for SeismicPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled>,
    Pooled: SignedTransaction + TryFrom<Cons, Error: core::error::Error>,
{
    type TryFromConsensusError = <Pooled as TryFrom<Cons>>::Error;
    type Consensus = Cons;
    type Pooled = Pooled;

    fn hash(&self) -> &TxHash {
        self.inner.transaction.tx_hash()
    }

    fn sender(&self) -> Address {
        self.inner.transaction.signer()
    }

    fn sender_ref(&self) -> &Address {
        self.inner.transaction.signer_ref()
    }

    fn cost(&self) -> &U256 {
        &self.inner.cost
    }

    fn encoded_length(&self) -> usize {
        self.inner.encoded_length
    }

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.transaction().clone()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.transaction
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let encoded_len = tx.encode_2718_len();
        Self::new(tx.convert(), encoded_len)
    }
}

impl<Cons: Typed2718, Pooled> Typed2718 for SeismicPooledTransaction<Cons, Pooled> {
    fn ty(&self) -> u8 {
        self.inner.ty()
    }
}

impl<Cons: InMemorySize, Pooled> InMemorySize for SeismicPooledTransaction<Cons, Pooled> {
    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl<Cons, Pooled> alloy_consensus::Transaction for SeismicPooledTransaction<Cons, Pooled>
where
    Cons: alloy_consensus::Transaction + SignedTransaction, // Ensure Cons has the methods
    Pooled: Debug + Send + Sync + 'static,                  /* From Optimism example, for
                                                             * completeness */
{
    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }
    fn nonce(&self) -> u64 {
        self.inner.nonce()
    }
    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }
    fn gas_price(&self) -> Option<u128> {
        self.inner.gas_price()
    }
    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.max_fee_per_blob_gas()
    }
    fn value(&self) -> U256 {
        self.inner.value()
    }
    fn input(&self) -> &Bytes {
        self.inner.input()
    }
    fn access_list(&self) -> Option<&AccessList> {
        self.inner.access_list()
    }
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.inner.blob_versioned_hashes()
    }
    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.inner.authorization_list()
    }
    fn priority_fee_or_price(&self) -> u128 {
        self.inner.priority_fee_or_price()
    }
    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.inner.effective_gas_price(base_fee)
    }
    fn is_dynamic_fee(&self) -> bool {
        self.inner.is_dynamic_fee()
    }
    fn kind(&self) -> TxKind {
        self.inner.kind()
    }
    fn is_create(&self) -> bool {
        self.inner.is_create()
    }
}

impl<Cons, Pooled> EthPoolTransaction for SeismicPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled>,
    Pooled: SignedTransaction + TryFrom<Cons>,
    <Pooled as TryFrom<Cons>>::Error: core::error::Error,
{
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecar>,
    ) -> Option<Recovered<Self::Pooled>> {
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecar,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecar,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(self.ty()))
    }
}

#[cfg(test)]
mod tests {
    use crate::SeismicPooledTransaction;
    use alloy_consensus::transaction::Recovered;
    use alloy_eips::eip2718::Encodable2718;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use reth_provider::test_utils::MockEthProvider;
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use reth_seismic_primitives::test_utils::get_signed_seismic_tx;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, error::InvalidPoolTransactionError,
        validate::EthTransactionValidatorBuilder, TransactionOrigin, TransactionValidationOutcome,
    };

    #[tokio::test]
    async fn validate_seismic_transaction() {
        // setup validator
        let client = MockEthProvider::default().with_chain_spec(SEISMIC_MAINNET.clone());
        let validator = EthTransactionValidatorBuilder::new(client)
            .no_shanghai()
            .no_cancun()
            .build(InMemoryBlobStore::default());

        // check that a SeismicTypedTransaction::Seismic is valid
        let origin = TransactionOrigin::External;
        let signer = Default::default();
        let signed_seismic_tx = get_signed_seismic_tx();
        let signed_recovered = Recovered::new_unchecked(signed_seismic_tx, signer);
        let len = signed_recovered.encode_2718_len();
        let pooled_tx: SeismicPooledTransaction =
            SeismicPooledTransaction::new(signed_recovered, len);

        let outcome = validator.validate_one(origin, pooled_tx);

        match outcome {
            TransactionValidationOutcome::Invalid(
                _,
                InvalidPoolTransactionError::Consensus(InvalidTransactionError::InsufficientFunds(
                    _,
                )),
            ) => {
                // expected since the client (MockEthProvider) state does not have funds for any
                // accounts account balance is one of the last things checked in
                // validate_one, so getting that far good news
            }
            _ => panic!("Did not get expected outcome, got: {:?}", outcome),
        }
    }
}
