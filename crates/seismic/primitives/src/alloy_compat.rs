//! Common conversions from alloy types.

use crate::SeismicTransactionSigned;
use alloy_consensus::TxEnvelope;
use alloy_network::{AnyRpcTransaction, AnyTxEnvelope};
use alloy_rpc_types_eth::{ConversionError, Transaction as AlloyRpcTransaction};
use alloy_serde::WithOtherFields;
use seismic_alloy_consensus::SeismicTypedTransaction;

impl TryFrom<AnyRpcTransaction> for SeismicTransactionSigned {
    type Error = ConversionError;

    fn try_from(tx: AnyRpcTransaction) -> Result<Self, Self::Error> {
        let WithOtherFields { inner: AlloyRpcTransaction { inner, .. }, other: _ } = tx.0;
        let from = inner.signer();

        let (transaction, signature, hash) = match inner.into_inner() {
            AnyTxEnvelope::Ethereum(TxEnvelope::Legacy(tx)) => {
                let (tx, signature, hash) = tx.into_parts();
                (SeismicTypedTransaction::Legacy(tx), signature, hash)
            }
            AnyTxEnvelope::Ethereum(TxEnvelope::Eip2930(tx)) => {
                let (tx, signature, hash) = tx.into_parts();
                (SeismicTypedTransaction::Eip2930(tx), signature, hash)
            }
            AnyTxEnvelope::Ethereum(TxEnvelope::Eip1559(tx)) => {
                let (tx, signature, hash) = tx.into_parts();
                (SeismicTypedTransaction::Eip1559(tx), signature, hash)
            }
            AnyTxEnvelope::Ethereum(TxEnvelope::Eip7702(tx)) => {
                let (tx, signature, hash) = tx.into_parts();
                (SeismicTypedTransaction::Eip7702(tx), signature, hash)
            }
            _ => return Err(ConversionError::Custom("unknown transaction type".to_string())),
        };

        Ok(Self::new(transaction, signature, hash))
    }
}

impl<T> From<AlloyRpcTransaction<T>> for SeismicTransactionSigned
where
    Self: From<T>,
{
    fn from(value: AlloyRpcTransaction<T>) -> Self {
        value.inner.into_inner().into()
    }
}