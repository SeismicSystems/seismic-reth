use alloy_consensus::{
    error::ValueError, transaction::Recovered, BlobTransactionValidationError, EthereumTxEnvelope,
    Signed, Typed2718,
};
use alloy_eips::{
    eip2930::AccessList, eip7594::BlobTransactionSidecarVariant, eip7702::SignedAuthorization,
    Encodable2718,
};
use alloy_primitives::{Address, Bytes, TxHash, TxKind, B256, U256};
use c_kzg::KzgSettings;
use core::fmt::Debug;
use reth_primitives_traits::{Extended, InMemorySize, SignedTransaction};
use reth_seismic_primitives::{SeismicPooledTransactionVariant, SeismicTransactionSigned};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};
use seismic_alloy_consensus::SeismicTypedTransaction;
use std::sync::Arc;

/// Pool Transaction for Seismic.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct SeismicPooledTransaction<
    Cons = SeismicTransactionSigned,
    Pooled = SeismicPooledTransactionVariant,
> {
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

impl PoolTransaction for SeismicPooledTransaction {
    type TryFromConsensusError = ValueError<SeismicTransactionSigned>;
    type Consensus = SeismicTransactionSigned;
    type Pooled = SeismicPooledTransactionVariant;

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
        let (tx, signer) = tx.into_parts();
        match tx {
            Extended::BuiltIn(EthereumTxEnvelope::Eip4844(tx)) => {
                let (tx, signature, hash) = tx.into_parts();
                let (tx, blob) = tx.into_parts();
                let tx = SeismicTransactionSigned::from(Signed::new_unchecked(tx, signature, hash));
                let tx = Recovered::new_unchecked(tx, signer);
                let mut pooled = Self::new(tx, encoded_len);
                pooled.inner.blob_sidecar = EthBlobTransactionSidecar::Present(blob);
                pooled
            }
            tx => {
                let tx = Recovered::new_unchecked(tx.into(), signer);
                Self::new(tx, encoded_len)
            }
        }
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

impl EthPoolTransaction for SeismicPooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        if self.is_eip4844() {
            std::mem::replace(&mut self.inner.blob_sidecar, EthBlobTransactionSidecar::Missing)
        } else {
            EthBlobTransactionSidecar::None
        }
    }

    fn try_into_pooled_eip4844(
        self,
        sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        let (tx, signer) = self.into_consensus().into_parts();
        attach_blob_sidecar(tx, Arc::unwrap_or_clone(sidecar))
            .map(|tx| Recovered::new_unchecked(tx, signer))
    }

    fn try_from_eip4844(
        tx: Recovered<Self::Consensus>,
        sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        let (tx, signer) = tx.into_parts();
        attach_blob_sidecar(tx, sidecar)
            .map(|tx| Recovered::new_unchecked(tx, signer))
            .map(Self::from_pooled)
    }

    fn validate_blob(
        &self,
        sidecar: &BlobTransactionSidecarVariant,
        settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        match self.inner.transaction.inner().transaction() {
            SeismicTypedTransaction::Eip4844(tx) => tx.validate_blob(sidecar, settings),
            _ => Err(BlobTransactionValidationError::NotBlobTransaction(self.ty())),
        }
    }
}

fn attach_blob_sidecar(
    tx: SeismicTransactionSigned,
    sidecar: BlobTransactionSidecarVariant,
) -> Option<SeismicPooledTransactionVariant> {
    let (tx, signature, hash) = tx.into_parts();
    let SeismicTypedTransaction::Eip4844(tx) = tx else { return None };
    let tx = Signed::new_unchecked(tx.with_sidecar(sidecar), signature, hash);
    Some(Extended::BuiltIn(EthereumTxEnvelope::Eip4844(tx)))
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test code - expect on failure is acceptable
#[allow(clippy::unwrap_used)] // Test code - unwrap on failure is acceptable
#[allow(clippy::panic)] // Test code - panic on failure is acceptable
mod tests {
    use crate::SeismicPooledTransaction;
    use alloy_consensus::{
        transaction::Recovered, EthereumTxEnvelope, Signed, TxEip1559, TxEip4844,
    };
    use alloy_eips::{
        eip2718::Encodable2718, eip4844::BlobTransactionSidecar,
        eip7594::BlobTransactionSidecarVariant,
    };
    use alloy_primitives::{Address, Signature, B256, U256};
    use reth_primitives_traits::{transaction::error::InvalidTransactionError, Extended};
    use reth_provider::test_utils::MockEthProvider;
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use reth_seismic_primitives::{SeismicPooledTransactionVariant, SeismicTransactionSigned};
    use reth_seismic_test_utils::get_signed_seismic_tx;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, error::InvalidPoolTransactionError,
        validate::EthTransactionValidatorBuilder, EthBlobTransactionSidecar, EthPoolTransaction,
        PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    };
    use seismic_alloy_consensus::SeismicTxEnvelope;
    use std::sync::Arc;

    fn pooled_blob_transaction() -> (SeismicPooledTransactionVariant, BlobTransactionSidecarVariant)
    {
        let sidecar = BlobTransactionSidecarVariant::Eip4844(BlobTransactionSidecar::default());
        let signature = Signature::new(U256::from(1), U256::from(1), false);
        let tx = TxEip4844::default().with_sidecar(sidecar.clone());
        let tx = Signed::new_unchecked(tx, signature, B256::repeat_byte(3));
        (Extended::BuiltIn(EthereumTxEnvelope::Eip4844(tx)), sidecar)
    }

    #[test]
    fn pooled_conversion_uses_non_overlapping_branches() {
        let seismic = get_signed_seismic_tx(B256::ZERO);
        let pooled = SeismicPooledTransactionVariant::try_from(seismic.clone())
            .expect("seismic transaction should be poolable");
        assert!(matches!(&pooled, Extended::Other(SeismicTxEnvelope::Seismic(_))));
        assert_eq!(SeismicTransactionSigned::from(pooled), seismic);

        let signature = Signature::new(U256::from(1), U256::from(1), false);
        let ethereum = SeismicTransactionSigned::from(Signed::new_unchecked(
            TxEip1559::default(),
            signature,
            B256::repeat_byte(1),
        ));
        let pooled = SeismicPooledTransactionVariant::try_from(ethereum.clone())
            .expect("EIP-1559 transaction should be poolable");
        assert!(matches!(&pooled, Extended::BuiltIn(EthereumTxEnvelope::Eip1559(_))));
        assert_eq!(SeismicTransactionSigned::from(pooled), ethereum);
    }

    #[test]
    fn consensus_eip4844_requires_sidecar_for_pooled_conversion() {
        let signature = Signature::new(U256::from(1), U256::from(1), false);
        let consensus = SeismicTransactionSigned::from(Signed::new_unchecked(
            TxEip4844::default(),
            signature,
            B256::repeat_byte(3),
        ));

        let err = SeismicPooledTransactionVariant::try_from(consensus.clone())
            .expect_err("consensus EIP-4844 transaction must not pool without a sidecar");
        assert_eq!(err.into_value(), consensus);
    }

    #[test]
    fn pooled_blob_sidecar_is_stripped_and_retained() {
        let (tx, sidecar) = pooled_blob_transaction();
        let encoded_length = tx.encode_2718_len();
        let recovered = Recovered::new_unchecked(tx, Address::repeat_byte(1));
        let mut pooled = SeismicPooledTransaction::from_pooled(recovered);

        assert_eq!(pooled.encoded_length(), encoded_length);
        assert!(encoded_length > pooled.clone_into_consensus().encode_2718_len());
        let repropagated = pooled
            .clone()
            .try_into_pooled_eip4844(Arc::new(sidecar.clone()))
            .expect("blob sidecar should reattach for propagation");
        assert_eq!(repropagated.encode_2718_len(), encoded_length);
        assert_eq!(pooled.take_blob(), EthBlobTransactionSidecar::Present(sidecar.clone()));

        let consensus = pooled.clone_into_consensus();
        let mut reattached = SeismicPooledTransaction::try_from_eip4844(consensus, sidecar.clone())
            .expect("consensus blob transaction should accept a sidecar");
        assert_eq!(reattached.take_blob(), EthBlobTransactionSidecar::Present(sidecar));
    }

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
        let signed_seismic_tx = get_signed_seismic_tx(B256::ZERO);
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
