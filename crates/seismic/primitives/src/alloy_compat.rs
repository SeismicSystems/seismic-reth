//! Common conversions from alloy types.

use crate::SeismicTransactionSigned;
use alloy_consensus::TxEnvelope;
use alloy_network::{AnyRpcTransaction, AnyTxEnvelope};
use alloy_primitives::PrimitiveSignature;
use alloy_rpc_types_eth::{ConversionError, Transaction as AlloyRpcTransaction};
use alloy_serde::WithOtherFields;
use seismic_alloy_consensus::{transaction::TxSeismicElements, SeismicTypedTransaction, TxSeismic};

macro_rules! get_field {
    ($fields:expr, $key:expr) => {
        $fields
            .get_deserialized($key)
            .and_then(Result::ok)
            .ok_or(ConversionError::Custom(format!("missing field: {}", $key)))?
    };
}

impl TryFrom<AnyRpcTransaction> for SeismicTransactionSigned {
    type Error = ConversionError;

    fn try_from(tx: AnyRpcTransaction) -> Result<Self, Self::Error> {
        let WithOtherFields { inner: AlloyRpcTransaction { inner, .. }, other: _ } = tx.0;

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
            AnyTxEnvelope::Unknown(tx) => {
                let inner = tx.inner.clone();
                let hash = tx.hash;
                let fields = inner.fields;

                println!("fields: {:?}\n", fields);

                let y_parity: String = get_field!(fields, "yParity");
                let signature = PrimitiveSignature::new(
                    get_field!(fields, "r"),
                    get_field!(fields, "s"),
                    y_parity == "0x0",
                );

                let seismic_elements = TxSeismicElements {
                    encryption_pubkey: get_field!(fields, "encryptionPubkey"),
                    encryption_nonce: get_field!(fields, "encryptionNonce"),
                    message_version: get_field!(fields, "messageVersion"),
                };

                let tx_seismic = TxSeismic {
                    chain_id: get_field!(fields, "chainId"),
                    nonce: get_field!(fields, "nonce"),
                    gas_price: get_field!(fields, "gasPrice"),
                    gas_limit: get_field!(fields, "gas"),
                    to: get_field!(fields, "to"),
                    value: get_field!(fields, "value"),
                    input: get_field!(fields, "input"),
                    seismic_elements,
                };

                (SeismicTypedTransaction::Seismic(tx_seismic), signature, hash)
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

#[cfg(test)]
mod tests {
    use alloy_network::AnyRpcTransaction;
    use crate::SeismicTransactionSigned;

    #[test]
    fn test_tx_with_seismic_elements() -> Result<(), Box<dyn std::error::Error>> {
        // json based on crate::test_utils::get_signed_seismic_tx
        // first 5 fields picked off of the OP test case to make things compile
        let json = r#"{
            "hash": "0x3f44a72b1faf70be7295183f1f30cfb51ede92d7c44441ca80c9437a6a22e5a5",
            "blockHash": "0x0d7f8b9def6f5d3ba2cbeee2e31e730da81e2c474fa8c3c9e8d0e6b96e37d182",
            "blockNumber": "0x1966297",
            "transactionIndex": "0x1",
            "from": "0x977f82a600a1414e583f7f13623f1ac5d58b1c0b",
            "r": "0x76c0d0e3d16cb3981775f63f159bbe67ee4b3ea58da566c952b7fe437c0bc6a",
            "s": "0x786b92b719cc5082816733ecbb1c0fee4006e9763132d994450e5e85578303e3",
            "yParity": "0x0",
            "v": "0x0",
            "type": "0x4A",
            "chainId": "0x1403",
            "nonce": "0x1",
            "gasPrice": "0x4a817c800",
            "gas": "0x33450",
            "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "value": "0x1c6bf52634000",
            "input": "0x07b46d5eb63d4799e420e3ff1a27888a44c2d6505eac642061a2c290cdc45f2da8c5a13ede8eabfc9424bead86330c0b98a91e3b",
            "encryptionPubkey": "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
            "encryptionNonce": "0xffffffffffffffffffffffff",
            "messageVersion": "0x0"
        }"#;
        
        let tx: AnyRpcTransaction = serde_json::from_str(&json).unwrap();
        SeismicTransactionSigned::try_from(tx).unwrap();
        Ok(())
    }
}
