//! Compact implementation for [`AlloyTxSeismic`]

use crate::Compact;
use alloy_consensus::{
    transaction::{EncryptionPublicKey, TxSeismicElements},
    TxSeismic as AlloyTxSeismic,
};
use alloy_primitives::{Bytes, ChainId, TxKind, U256};

/// Seismic transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default, Compact)]
#[reth_codecs(crate = "crate")]
#[cfg_attr(
    any(test, feature = "test-utils"),
    derive(arbitrary::Arbitrary, serde::Serialize, serde::Deserialize),
    crate::add_arbitrary_tests(crate, compact)
)]
#[cfg_attr(feature = "test-utils", allow(unreachable_pub), visibility::make(pub))]
pub(crate) struct TxSeismic {
    /// Added as EIP-155: Simple replay attack protection
    chain_id: ChainId,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    gas_price: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    gas_limit: u64,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    value: U256,
    /// seismic elements
    seismic_elements: TxSeismicElements,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    input: Bytes,
}

impl Compact for TxSeismicElements {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut len = 0;
        len += self.encryption_pubkey.to_compact(buf);
        len += self.message_version.to_compact(buf);
        len
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (encryption_pubkey, buf) = EncryptionPublicKey::from_compact(buf, len);
        let (message_version, buf) = u8::from_compact(buf, len);
        let alloy_tx = Self { encryption_pubkey, message_version };
        (alloy_tx, buf)
    }
}

impl Compact for AlloyTxSeismic {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let tx = TxSeismic {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            seismic_elements: self.seismic_elements,
            input: self.input.clone(),
        };

        tx.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (tx, _) = TxSeismic::from_compact(buf, len);

        let alloy_tx = Self {
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            gas_price: tx.gas_price,
            gas_limit: tx.gas_limit,
            to: tx.to,
            value: tx.value,
            seismic_elements: tx.seismic_elements,
            input: tx.input,
        };

        (alloy_tx, buf)
    }
}
