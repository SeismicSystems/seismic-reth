//! Loads and formats Seismic receipt RPC response.

use alloy_consensus::Typed2718;
use alloy_eips::eip7840::BlobParams;
use reth_chainspec::EthChainSpec;
use reth_rpc_convert::transaction::{ConvertReceiptInput, ReceiptConverter};
use reth_rpc_eth_api::{helpers::LoadReceipt, RpcConvert, RpcNodeCore};
use reth_rpc_eth_types::{receipt::build_receipt, EthApiError};
use reth_rpc_server_types::result::internal_rpc_err;
use reth_seismic_primitives::{SeismicPrimitives, SeismicReceipt};
use seismic_alloy_consensus::SeismicReceiptEnvelope;
use seismic_alloy_rpc_types::SeismicTransactionReceipt;
use std::{fmt::Debug, sync::Arc};

use crate::{SeismicEthApi, SeismicEthApiError};

impl<N, Rpc> LoadReceipt for SeismicEthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = SeismicEthApiError>,
{
}

/// Builds an [`SeismicTransactionReceipt`].
///
/// Like [`EthReceiptBuilder`], but with Seismic types
#[derive(Debug)]
pub struct SeismicReceiptBuilder {
    /// The base response body, contains L1 fields.
    pub base: SeismicTransactionReceipt,
}

impl SeismicReceiptBuilder {
    /// Returns a new builder.
    pub fn new(
        input: ConvertReceiptInput<'_, SeismicPrimitives>,
        blob_params: Option<BlobParams>,
    ) -> Result<Self, EthApiError> {
        // The receipt and its transaction must agree on the transaction type.
        let receipt_ty = input.receipt.tx_type() as u8;
        let tx_ty = input.tx.ty();
        if receipt_ty != tx_ty {
            return Err(EthApiError::other(internal_rpc_err(format!(
                "receipt type {receipt_ty} does not match transaction type {tx_ty}"
            ))));
        }

        let base =
            build_receipt(&input, blob_params, |receipt_with_bloom| match input.receipt.as_ref() {
                SeismicReceipt::Legacy(_) => SeismicReceiptEnvelope::Legacy(receipt_with_bloom),
                SeismicReceipt::Eip2930(_) => SeismicReceiptEnvelope::Eip2930(receipt_with_bloom),
                SeismicReceipt::Eip1559(_) => SeismicReceiptEnvelope::Eip1559(receipt_with_bloom),
                SeismicReceipt::Eip7702(_) => SeismicReceiptEnvelope::Eip7702(receipt_with_bloom),
                SeismicReceipt::Seismic(_) => SeismicReceiptEnvelope::Seismic(receipt_with_bloom),
                SeismicReceipt::Eip4844(_) => SeismicReceiptEnvelope::Eip4844(receipt_with_bloom),
            });

        Ok(Self { base })
    }

    /// Builds [`SeismicTransactionReceipt`] by combing core (l1) receipt fields and additional
    /// Seismic receipt fields.
    pub fn build(self) -> SeismicTransactionReceipt {
        self.base
    }
}

trait BlobParamsProvider: Debug + Send + Sync {
    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams>;
}

impl<ChainSpec> BlobParamsProvider for ChainSpec
where
    ChainSpec: EthChainSpec,
{
    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        EthChainSpec::blob_params_at_timestamp(self, timestamp)
    }
}

/// Seismic receipt converter.
#[derive(Debug, Clone)]
pub struct SeismicReceiptConverter {
    // Erase the chain spec type to keep the public RPC converter alias non-generic.
    chain_spec: Arc<dyn BlobParamsProvider>,
}

impl SeismicReceiptConverter {
    /// Creates a new seismic receipt converter with the given chain spec.
    pub fn new<ChainSpec>(chain_spec: Arc<ChainSpec>) -> Self
    where
        ChainSpec: EthChainSpec + 'static,
    {
        Self { chain_spec }
    }
}

impl ReceiptConverter<SeismicPrimitives> for SeismicReceiptConverter {
    type Error = SeismicEthApiError;
    type RpcReceipt = SeismicTransactionReceipt;

    fn convert_receipts(
        &self,
        inputs: Vec<ConvertReceiptInput<'_, SeismicPrimitives>>,
    ) -> Result<Vec<Self::RpcReceipt>, Self::Error> {
        let mut receipts = Vec::with_capacity(inputs.len());

        for input in inputs {
            let timestamp_seconds = if cfg!(feature = "timestamp-in-seconds") {
                input.meta.timestamp
            } else {
                input.meta.timestamp / 1000
            };
            let blob_params = self.chain_spec.blob_params_at_timestamp(timestamp_seconds);
            receipts.push(
                SeismicReceiptBuilder::new(input, blob_params)
                    .map_err(SeismicEthApiError::Eth)?
                    .build(),
            );
        }

        Ok(receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{
        transaction::{Recovered, TransactionMeta},
        Eip658Value, Receipt, TxEip4844,
    };
    use alloy_eips::eip4844::{DATA_GAS_PER_BLOB, VERSIONED_HASH_VERSION_KZG};
    use alloy_primitives::{Address, Signature, B256, U256};
    use reth_seismic_chainspec::SEISMIC_MAINNET;
    use reth_seismic_primitives::SeismicTransactionSigned;
    use reth_seismic_test_utils::get_signed_seismic_tx;
    use seismic_alloy_consensus::SeismicTypedTransaction;
    use std::borrow::Cow;

    #[test]
    fn new_rejects_mismatched_receipt_and_tx_types() {
        // Seismic-typed transaction paired with a legacy-typed receipt.
        let tx = get_signed_seismic_tx(B256::ZERO);
        let receipt = SeismicReceipt::Legacy(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 0,
            logs: Vec::new(),
        });
        let input = ConvertReceiptInput {
            receipt: Cow::Owned(receipt),
            tx: Recovered::new_unchecked(&tx, Address::ZERO),
            gas_used: 0,
            next_log_index: 0,
            meta: TransactionMeta::default(),
        };
        assert!(SeismicReceiptBuilder::new(input, None).is_err());
    }

    #[test]
    fn eip4844_receipt_includes_blob_gas_price() {
        const EXCESS_BLOB_GAS: u64 = 10_000_000;

        let mut versioned_hash = [0u8; 32];
        versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
        let tx = SeismicTransactionSigned::new_unhashed(
            SeismicTypedTransaction::Eip4844(TxEip4844 {
                blob_versioned_hashes: vec![B256::from(versioned_hash)],
                ..Default::default()
            }),
            Signature::new(U256::from(1), U256::from(1), false),
        );
        let receipt = SeismicReceipt::Eip4844(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 0,
            logs: Vec::new(),
        });
        let input = ConvertReceiptInput {
            receipt: Cow::Owned(receipt),
            tx: Recovered::new_unchecked(&tx, Address::ZERO),
            gas_used: 0,
            next_log_index: 0,
            meta: TransactionMeta { excess_blob_gas: Some(EXCESS_BLOB_GAS), ..Default::default() },
        };

        let rpc_receipt = SeismicReceiptConverter::new(SEISMIC_MAINNET.clone())
            .convert_receipts(vec![input])
            .unwrap()
            .pop()
            .unwrap();
        let expected_blob_gas_price =
            EthChainSpec::blob_params_at_timestamp(SEISMIC_MAINNET.as_ref(), 0)
                .unwrap()
                .calc_blob_fee(EXCESS_BLOB_GAS);

        assert_eq!(rpc_receipt.blob_gas_price, Some(expected_blob_gas_price));
        assert_eq!(rpc_receipt.blob_gas_used, Some(DATA_GAS_PER_BLOB));
    }

    #[test]
    fn non_blob_receipt_omits_blob_gas_fields() {
        let tx = get_signed_seismic_tx(B256::ZERO);
        let receipt = SeismicReceipt::Seismic(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 0,
            logs: Vec::new(),
        });
        let input = ConvertReceiptInput {
            receipt: Cow::Owned(receipt),
            tx: Recovered::new_unchecked(&tx, Address::ZERO),
            gas_used: 0,
            next_log_index: 0,
            meta: TransactionMeta { excess_blob_gas: Some(10_000_000), ..Default::default() },
        };

        let rpc_receipt = SeismicReceiptConverter::new(SEISMIC_MAINNET.clone())
            .convert_receipts(vec![input])
            .unwrap()
            .pop()
            .unwrap();

        assert_eq!(rpc_receipt.blob_gas_price, None);
        assert_eq!(rpc_receipt.blob_gas_used, None);
    }
}
