//! A signed Seismic transaction.

use alloc::vec::Vec;
use alloy_consensus::{
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
    Sealed, SignableTransaction, Signed, Transaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy,
    Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{
    keccak256, Address, Bytes, PrimitiveSignature as Signature, TxHash, TxKind, Uint, B256,
};
use alloy_rlp::Header;
use core::{
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
};
use derive_more::{AsRef, Deref};
#[cfg(any(test, feature = "reth-codec"))]
use proptest as _;
use reth_codecs::alloy::signature;
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    sync::OnceLock,
    transaction::{error::TransactionConversionError, signed::RecoveryError},
    InMemorySize, SignedTransaction,
};
use revm_context::TxEnv;
use seismic_alloy_consensus::{
    SeismicTxEnvelope, SeismicTxType, SeismicTypedTransaction, TxSeismic,
};

impl SignedTransaction for SeismicTxEnvelope {
    fn tx_hash(&self) -> &TxHash {
        &self.tx_hash()
    }

    fn signature(&self) -> &Signature {
        &self.signature()
    }

    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        let signature_hash = signature_hash(self.tx());
        recover_signer(self.signature(), signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        let signature_hash = signature_hash(self.tx());
        recover_signer_unchecked(self.signature(), signature_hash)
    }

    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError> {
        self.recover_signer_unchecked()
    }

    fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }
}

impl FromRecoveredTx<SeismicTxEnvelope> for TxEnv {
    fn from_recovered_tx(signed_tx: &SeismicTxEnvelope, sender: Address) -> Self {
        match signed_tx.tx() {
            SeismicTypedTransaction::Legacy(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                gas_priority_fee: None,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: tx.chain_id,
                nonce: tx.nonce,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 0,
                caller: sender,
            },
            SeismicTypedTransaction::Eip2930(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                gas_priority_fee: None,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 1,
                caller: sender,
            },
            SeismicTypedTransaction::Eip1559(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                gas_priority_fee: Some(tx.max_priority_fee_per_gas),
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                tx_type: 2,
                caller: sender,
            },
            SeismicTypedTransaction::Eip7702(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: tx.max_fee_per_gas,
                gas_priority_fee: Some(tx.max_priority_fee_per_gas),
                kind: TxKind::Call(tx.to),
                value: tx.value,
                data: tx.input.clone(),
                chain_id: Some(tx.chain_id),
                nonce: tx.nonce,
                access_list: tx.access_list.clone(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: tx.authorization_list.clone(),
                tx_type: 4,
                caller: sender,
            },
            SeismicTypedTransaction::Seismic(tx) => TxEnv {
                gas_limit: tx.gas_limit,
                gas_price: 0,
                kind: tx.to,
                value: tx.value,
                data: tx.input.clone(),
                chain_id: None,
                nonce: 0,
                access_list: Default::default(),
                blob_hashes: Default::default(),
                max_fee_per_blob_gas: Default::default(),
                authorization_list: Default::default(),
                gas_priority_fee: Default::default(),
                tx_type: 126,
                caller: sender,
            },
        }
    }
}

impl InMemorySize for SeismicTypedTransaction {
    #[inline]
    fn size(&self) -> usize {
        match self {
            SeismicTypedTransaction::Legacy(tx) => tx.size(),
            SeismicTypedTransaction::Eip2930(tx) => tx.size(),
            SeismicTypedTransaction::Eip1559(tx) => tx.size(),
            SeismicTypedTransaction::Eip7702(tx) => tx.size(),
            SeismicTypedTransaction::Seismic(tx) => tx.size(),
        }
    }
}
impl InMemorySize for SeismicTxEnvelope {
    #[inline]
    fn size(&self) -> usize {
        mem::size_of::<TxHash>() +
            mem::size_of::<Signature>() +
            match self.tx() {
                SeismicTypedTransaction::Legacy(tx) => tx.size(),
                SeismicTypedTransaction::Eip2930(tx) => tx.size(),
                SeismicTypedTransaction::Eip1559(tx) => tx.size(),
                SeismicTypedTransaction::Eip7702(tx) => tx.size(),
                SeismicTypedTransaction::Seismic(tx) => tx.size(),
            }
    }
}

impl Hash for SeismicTxEnvelope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature().hash(state);
        match self.tx() {
            SeismicTypedTransaction::Legacy(tx) => tx.hash(state),
            SeismicTypedTransaction::Eip2930(tx) => tx.hash(state),
            SeismicTypedTransaction::Eip1559(tx) => tx.hash(state),
            SeismicTypedTransaction::Eip7702(tx) => tx.hash(state),
            SeismicTypedTransaction::Seismic(tx) => tx.hash(state),
        }
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for SeismicTypedTransaction {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        let identifier = self.tx_type().to_compact(buf);
        self.tx().to_compact(buf);
        identifier
    }

    fn from_compact(buf: &[u8], identifier: usize) -> (Self, &[u8]) {
        let (tx_type, buf) = TxType::from_compact(buf, identifier);

        match tx_type {
            SeismicTxType::Legacy => {
                let (tx, buf) = TxLegacy::from_compact(buf, buf.len());
                (Self::Legacy(tx), buf)
            }
            SeismicTxType::Eip1559 => {
                let (tx, buf) = TxEip1559::from_compact(buf, buf.len());
                (Self::Eip1559(tx), buf)
            }
            SeismicTxType::Eip2930 => {
                let (tx, buf) = TxEip2930::from_compact(buf, buf.len());
                (Self::Eip2930(tx), buf)
            }
            SeismicTxType::Eip7702 => {
                let (tx, buf) = TxEip7702::from_compact(buf, buf.len());
                (Self::Eip7702(tx), buf)
            }
            SeismicTxType::Seismic => {
                let (tx, buf) = TxSeismic::from_compact(buf, buf.len());
                (Self::Seismic(tx), buf)
            }
        }
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for SeismicTxEnvelope {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        use alloy_consensus::Transaction;

        let start = buf.as_mut().len();

        // Placeholder for bitflags.
        // The first byte uses 4 bits as flags: IsCompressed[1bit], TxType[2bits], Signature[1bit]
        buf.put_u8(0);

        let sig_bit = self.signature().to_compact(buf) as u8;
        let zstd_bit = self.tx().input().len() >= 32;

        let tx_bits = if zstd_bit {
            let mut tmp = Vec::with_capacity(256);
            if cfg!(feature = "std") {
                reth_zstd_compressors::TRANSACTION_COMPRESSOR.with(|compressor| {
                    let mut compressor = compressor.borrow_mut();
                    let tx_bits = self.tx().to_compact(&mut tmp);
                    buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                    tx_bits as u8
                })
            } else {
                let mut compressor = reth_zstd_compressors::create_tx_compressor();
                let tx_bits = self.tx().to_compact(&mut tmp);
                buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                tx_bits as u8
            }
        } else {
            self.tx().to_compact(buf) as u8
        };

        // Replace bitflags with the actual values
        buf.as_mut()[start] = sig_bit | (tx_bits << 1) | ((zstd_bit as u8) << 3);

        buf.as_mut().len() - start
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use alloy_rlp::bytes::Buf;

        // The first byte uses 4 bits as flags: IsCompressed[1], TxType[2], Signature[1]
        let bitflags = buf.get_u8() as usize;

        let sig_bit = bitflags & 1;
        let (signature, buf) = Signature::from_compact(buf, sig_bit);

        let zstd_bit = bitflags >> 3;
        let (transaction, buf) = if zstd_bit != 0 {
            if cfg!(feature = "std") {
                reth_zstd_compressors::TRANSACTION_DECOMPRESSOR.with(|decompressor| {
                    let mut decompressor = decompressor.borrow_mut();

                    // TODO: enforce that zstd is only present at a "top" level type

                    let transaction_type = (bitflags & 0b110) >> 1;
                    let (transaction, _) = SeismicTypedTransaction::from_compact(
                        decompressor.decompress(buf),
                        transaction_type,
                    );

                    (transaction, buf)
                })
            } else {
                let mut decompressor = reth_zstd_compressors::create_tx_decompressor();
                let transaction_type = (bitflags & 0b110) >> 1;
                let (transaction, _) = SeismicTypedTransaction::from_compact(
                    decompressor.decompress(buf),
                    transaction_type,
                );

                (transaction, buf)
            }
        } else {
            let transaction_type = bitflags >> 1;
            SeismicTypedTransaction::from_compact(buf, transaction_type)
        };

        (Self::new_unhashed(transaction, signature), buf)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for SeismicTxEnvelope {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        #[allow(unused_mut)]
        let mut transaction = SeismicTypedTransaction::arbitrary(u)?;

        let secp = secp256k1::Secp256k1::new();
        let key_pair = secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        let signature = reth_primitives_traits::crypto::secp256k1::sign_message(
            B256::from_slice(&key_pair.secret_bytes()[..]),
            transaction.signature_hash(),
        )
        .unwrap();

        Ok(Self::new_unhashed(transaction, signature))
    }
}

/// Bincode-compatible transaction type serde implementations.
#[cfg(feature = "serde-bincode-compat")]
pub mod serde_bincode_compat {
    use alloy_consensus::transaction::serde_bincode_compat::{
        TxEip1559, TxEip2930, TxEip7702, TxLegacy,
    };
    use alloy_primitives::{PrimitiveSignature as Signature, TxHash};
    use reth_primitives_traits::{serde_bincode_compat::SerdeBincodeCompat, SignedTransaction};
    use serde::{Deserialize, Serialize};

    /// Bincode-compatible [`super::SeismicTypedTransaction`] serde implementation.
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(missing_docs)]
    enum SeismicTypedTransaction<'a> {
        Legacy(TxLegacy<'a>),
        Eip2930(TxEip2930<'a>),
        Eip1559(TxEip1559<'a>),
        Eip7702(TxEip7702<'a>),
        Deposit(seismic_alloy_consensus::serde_bincode_compat::TxSeismic<'a>),
    }

    impl<'a> From<&'a super::SeismicTypedTransaction> for SeismicTypedTransaction<'a> {
        fn from(value: &'a super::SeismicTypedTransaction) -> Self {
            match value {
                super::SeismicTypedTransaction::Legacy(tx) => Self::Legacy(TxLegacy::from(tx)),
                super::SeismicTypedTransaction::Eip2930(tx) => Self::Eip2930(TxEip2930::from(tx)),
                super::SeismicTypedTransaction::Eip1559(tx) => Self::Eip1559(TxEip1559::from(tx)),
                super::SeismicTypedTransaction::Eip7702(tx) => Self::Eip7702(TxEip7702::from(tx)),
                super::SeismicTypedTransaction::Seismic(tx) => Self::Seismic(TxSeismic::from(tx)),
            }
        }
    }

    impl<'a> From<SeismicTypedTransaction<'a>> for super::SeismicTypedTransaction {
        fn from(value: SeismicTypedTransaction<'a>) -> Self {
            match value {
                SeismicTypedTransaction::Legacy(tx) => Self::Legacy(tx.into()),
                SeismicTypedTransaction::Eip2930(tx) => Self::Eip2930(tx.into()),
                SeismicTypedTransaction::Eip1559(tx) => Self::Eip1559(tx.into()),
                SeismicTypedTransaction::Eip7702(tx) => Self::Eip7702(tx.into()),
                SeismicTypedTransaction::Seismic(tx) => Self::Seismic(tx.into()),
            }
        }
    }

    /// Bincode-compatible [`super::SeismicTransactionSigned`] serde implementation.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SeismicTransactionSigned<'a> {
        hash: TxHash,
        signature: Signature,
        transaction: SeismicTypedTransaction<'a>,
    }

    impl<'a> From<&'a super::SeismicTransactionSigned> for SeismicTransactionSigned<'a> {
        fn from(value: &'a super::SeismicTransactionSigned) -> Self {
            Self {
                hash: *value.tx_hash(),
                signature: value.signature,
                transaction: SeismicTypedTransaction::from(&value.transaction),
            }
        }
    }

    impl<'a> From<SeismicTransactionSigned<'a>> for super::SeismicTransactionSigned {
        fn from(value: SeismicTransactionSigned<'a>) -> Self {
            Self {
                hash: value.hash.into(),
                signature: value.signature,
                transaction: value.transaction.into(),
            }
        }
    }

    impl SerdeBincodeCompat for super::SeismicTransactionSigned {
        type BincodeRepr<'a> = SeismicTransactionSigned<'a>;

        fn as_repr(&self) -> Self::BincodeRepr<'_> {
            self.into()
        }

        fn from_repr(repr: Self::BincodeRepr<'_>) -> Self {
            repr.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::proptest;
    use proptest_arbitrary_interop::arb;
    use reth_codecs::Compact;

    proptest! {
        #[test]
        fn test_roundtrip_compact_encode_envelope(reth_tx in arb::<SeismicTransactionSigned>()) {
            let mut expected_buf = Vec::<u8>::new();
            let expected_len = reth_tx.to_compact(&mut expected_buf);

            let mut actual_but  = Vec::<u8>::new();
            let alloy_tx = SeismicTxEnvelope::from(reth_tx);
            let actual_len = alloy_tx.to_compact(&mut actual_but);

            assert_eq!(actual_but, expected_buf);
            assert_eq!(actual_len, expected_len);
        }

        #[test]
        fn test_roundtrip_compact_decode_envelope(reth_tx in arb::<SeismicTransactionSigned>()) {
            let mut buf = Vec::<u8>::new();
            let len = reth_tx.to_compact(&mut buf);

            let (actual_tx, _) = SeismicTxEnvelope::from_compact(&buf, len);
            let expected_tx = SeismicTxEnvelope::from(reth_tx);

            assert_eq!(actual_tx, expected_tx);
        }
    }
}
