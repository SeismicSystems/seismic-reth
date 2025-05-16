//! A signed Optimism transaction.

use alloc::vec::Vec;
use alloy_consensus::{
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
    SignableTransaction, Signed, Transaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy, Typed2718,
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
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    sync::OnceLock,
    transaction::signed::RecoveryError,
    InMemorySize, SignedTransaction,
};
use revm_context::TxEnv;
use seismic_alloy_consensus::{
    Decodable712, SeismicTxEnvelope, SeismicTypedTransaction, TxSeismic,
};
use seismic_revm::SeismicTransaction;

/// Signed transaction.
///
/// [`SeismicTransactionSigned`] is a wrapper around a [`SeismicTypedTransaction`] enum,
/// which can be Seismic(TxSeismic) with additional fields, or Ethereum compatible transactions.
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(rlp))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Eq, AsRef, Deref)]
pub struct SeismicTransactionSigned {
    /// Transaction hash
    #[cfg_attr(feature = "serde", serde(skip))]
    hash: OnceLock<TxHash>,
    /// The transaction signature values
    signature: Signature,
    /// Raw transaction info
    #[deref]
    #[as_ref]
    transaction: SeismicTypedTransaction,
}

impl SeismicTransactionSigned {
    /// Creates a new signed transaction from the given transaction, signature and hash.
    pub fn new(transaction: SeismicTypedTransaction, signature: Signature, hash: B256) -> Self {
        Self { hash: hash.into(), signature, transaction }
    }

    /// Consumes the type and returns the transaction.
    #[inline]
    pub fn into_transaction(self) -> SeismicTypedTransaction {
        self.transaction
    }

    /// Returns the transaction.
    #[inline]
    pub const fn transaction(&self) -> &SeismicTypedTransaction {
        &self.transaction
    }

    /// Splits the `SeismicTransactionSigned` into its transaction and signature.
    pub fn split(self) -> (SeismicTypedTransaction, Signature) {
        (self.transaction, self.signature)
    }

    /// Creates a new signed transaction from the given transaction and signature without the hash.
    ///
    /// Note: this only calculates the hash on the first [`SeismicTransactionSigned::hash`] call.
    pub fn new_unhashed(transaction: SeismicTypedTransaction, signature: Signature) -> Self {
        Self { hash: Default::default(), signature, transaction }
    }

    /// Splits the transaction into parts.
    pub fn into_parts(self) -> (SeismicTypedTransaction, Signature, B256) {
        let hash = *self.hash.get_or_init(|| self.recalculate_hash());
        (self.transaction, self.signature, hash)
    }
}

impl Decodable712 for SeismicTransactionSigned {
    fn decode_712(
        _buf: &seismic_alloy_consensus::TypedDataRequest,
    ) -> seismic_alloy_consensus::Eip712Result<Self> {
        todo!("todo: Decodable712 for SeismicTransactionSigned")
    }
}

impl SignedTransaction for SeismicTransactionSigned {
    fn tx_hash(&self) -> &TxHash {
        self.hash.get_or_init(|| self.recalculate_hash())
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        let Self { transaction, signature, .. } = self;
        let signature_hash = signature_hash(transaction);
        recover_signer(signature, signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        let Self { transaction, signature, .. } = self;
        let signature_hash = signature_hash(transaction);
        recover_signer_unchecked(signature, signature_hash)
    }

    fn recover_signer_unchecked_with_buf(
        &self,
        buf: &mut Vec<u8>,
    ) -> Result<Address, RecoveryError> {
        match &self.transaction {
            SeismicTypedTransaction::Legacy(tx) => tx.encode_for_signing(buf),
            SeismicTypedTransaction::Eip2930(tx) => tx.encode_for_signing(buf),
            SeismicTypedTransaction::Eip1559(tx) => tx.encode_for_signing(buf),
            SeismicTypedTransaction::Eip7702(tx) => tx.encode_for_signing(buf),
            SeismicTypedTransaction::Seismic(tx) => tx.encode_for_signing(buf),
        };
        recover_signer_unchecked(&self.signature, keccak256(buf))
    }

    fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }
}

macro_rules! impl_from_signed {
    ($($tx:ident),*) => {
        $(
            impl From<Signed<$tx>> for SeismicTransactionSigned {
                fn from(value: Signed<$tx>) -> Self {
                    let(tx,sig,hash) = value.into_parts();
                    Self::new(tx.into(), sig, hash)
                }
            }
        )*
    };
}

impl_from_signed!(TxLegacy, TxEip2930, TxEip1559, TxEip7702, TxSeismic, SeismicTypedTransaction);

impl From<SeismicTxEnvelope> for SeismicTransactionSigned {
    fn from(value: SeismicTxEnvelope) -> Self {
        match value {
            SeismicTxEnvelope::Legacy(tx) => tx.into(),
            SeismicTxEnvelope::Eip2930(tx) => tx.into(),
            SeismicTxEnvelope::Eip1559(tx) => tx.into(),
            SeismicTxEnvelope::Eip7702(tx) => tx.into(),
            SeismicTxEnvelope::Seismic(tx) => tx.into(),
        }
    }
}

impl From<SeismicTransactionSigned> for SeismicTxEnvelope {
    fn from(value: SeismicTransactionSigned) -> Self {
        let (tx, signature, hash) = value.into_parts();
        match tx {
            SeismicTypedTransaction::Legacy(tx) => {
                Signed::new_unchecked(tx, signature, hash).into()
            }
            SeismicTypedTransaction::Eip2930(tx) => {
                Signed::new_unchecked(tx, signature, hash).into()
            }
            SeismicTypedTransaction::Eip1559(tx) => {
                Signed::new_unchecked(tx, signature, hash).into()
            }
            SeismicTypedTransaction::Seismic(tx) => {
                Signed::new_unchecked(tx, signature, hash).into()
            }
            SeismicTypedTransaction::Eip7702(tx) => {
                Signed::new_unchecked(tx, signature, hash).into()
            }
        }
    }
}

impl From<SeismicTransactionSigned> for Signed<SeismicTypedTransaction> {
    fn from(value: SeismicTransactionSigned) -> Self {
        let (tx, sig, hash) = value.into_parts();
        Self::new_unchecked(tx, sig, hash)
    }
}

/// A trait that represents an optimism transaction, mainly used to indicate whether or not the
/// transaction is a deposit transaction.
pub trait OpTransaction {
    /// Whether or not the transaction is a dpeosit transaction.
    fn is_deposit(&self) -> bool;
}

impl OpTransaction for SeismicTransactionSigned {
    fn is_deposit(&self) -> bool {
        false // Seismic doesn't have deposit enum for [`SeismicTypedTransaction`]
    }
}

use seismic_revm::transaction::abstraction::RngMode;
impl FromRecoveredTx<SeismicTransactionSigned> for SeismicTransaction<TxEnv> {
    fn from_recovered_tx(tx: &SeismicTransactionSigned, sender: Address) -> Self {
        let tx_hash = tx.hash.get().unwrap().clone();
        let rng_mode = RngMode::Execution; // TODO WARNING: chose a default value
        let tx = match &tx.transaction {
            SeismicTypedTransaction::Legacy(tx) => SeismicTransaction::<TxEnv> {
                base: TxEnv {
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
                tx_hash,
                rng_mode,
            },
            SeismicTypedTransaction::Eip2930(tx) => SeismicTransaction::<TxEnv> {
                base: TxEnv {
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
                tx_hash,
                rng_mode,
            },
            SeismicTypedTransaction::Eip1559(tx) => SeismicTransaction::<TxEnv> {
                base: TxEnv {
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
                tx_hash,
                rng_mode,
            },
            SeismicTypedTransaction::Eip7702(tx) => SeismicTransaction::<TxEnv> {
                base: TxEnv {
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
                tx_hash,
                rng_mode,
            },
            SeismicTypedTransaction::Seismic(tx) => SeismicTransaction::<TxEnv> {
                base: TxEnv {
                    gas_limit: tx.gas_limit,
                    gas_price: tx.gas_price,
                    gas_priority_fee: None,
                    kind: tx.to,
                    value: tx.value,
                    data: tx.input.clone(),
                    chain_id: Some(tx.chain_id),
                    nonce: tx.nonce,
                    access_list: Default::default(),
                    blob_hashes: Default::default(),
                    max_fee_per_blob_gas: Default::default(),
                    authorization_list: Default::default(),
                    tx_type: TxSeismic::TX_TYPE,
                    caller: sender,
                },
                tx_hash,
                rng_mode,
            },
        };
        println!("from_recovered_tx: tx: {:?}", tx);
        tx
    }
}

impl InMemorySize for SeismicTransactionSigned {
    #[inline]
    fn size(&self) -> usize {
        mem::size_of::<TxHash>() + self.transaction.size() + mem::size_of::<Signature>()
    }
}

impl alloy_rlp::Encodable for SeismicTransactionSigned {
    fn encode(&self, out: &mut dyn alloy_rlp::bytes::BufMut) {
        self.network_encode(out);
    }

    fn length(&self) -> usize {
        let mut payload_length = self.encode_2718_len();
        if !self.is_legacy() {
            payload_length += Header { list: false, payload_length }.length();
        }

        payload_length
    }
}

impl alloy_rlp::Decodable for SeismicTransactionSigned {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::network_decode(buf).map_err(Into::into)
    }
}

impl Encodable2718 for SeismicTransactionSigned {
    fn type_flag(&self) -> Option<u8> {
        if Typed2718::is_legacy(self) {
            None
        } else {
            Some(self.ty())
        }
    }

    fn encode_2718_len(&self) -> usize {
        match &self.transaction {
            SeismicTypedTransaction::Legacy(legacy_tx) => {
                legacy_tx.eip2718_encoded_length(&self.signature)
            }
            SeismicTypedTransaction::Eip2930(access_list_tx) => {
                access_list_tx.eip2718_encoded_length(&self.signature)
            }
            SeismicTypedTransaction::Eip1559(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encoded_length(&self.signature)
            }
            SeismicTypedTransaction::Eip7702(set_code_tx) => {
                set_code_tx.eip2718_encoded_length(&self.signature)
            }
            SeismicTypedTransaction::Seismic(seismic_tx) => {
                seismic_tx.eip2718_encoded_length(&self.signature)
            }
        }
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        let Self { transaction, signature, .. } = self;

        match &transaction {
            SeismicTypedTransaction::Legacy(legacy_tx) => {
                // do nothing w/ with_header
                legacy_tx.eip2718_encode(signature, out)
            }
            SeismicTypedTransaction::Eip2930(access_list_tx) => {
                access_list_tx.eip2718_encode(signature, out)
            }
            SeismicTypedTransaction::Eip1559(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encode(signature, out)
            }
            SeismicTypedTransaction::Eip7702(set_code_tx) => {
                set_code_tx.eip2718_encode(signature, out)
            }
            SeismicTypedTransaction::Seismic(seismic_tx) => {
                seismic_tx.eip2718_encode(signature, out)
            }
        }
    }
}

impl Decodable2718 for SeismicTransactionSigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        match ty.try_into().map_err(|_| Eip2718Error::UnexpectedType(ty))? {
            seismic_alloy_consensus::SeismicTxType::Legacy => Err(Eip2718Error::UnexpectedType(0)),
            seismic_alloy_consensus::SeismicTxType::Eip2930 => {
                let (tx, signature, hash) = TxEip2930::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SeismicTypedTransaction::Eip2930(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            seismic_alloy_consensus::SeismicTxType::Eip1559 => {
                let (tx, signature, hash) = TxEip1559::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SeismicTypedTransaction::Eip1559(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            seismic_alloy_consensus::SeismicTxType::Eip7702 => {
                let (tx, signature, hash) = TxEip7702::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SeismicTypedTransaction::Eip7702(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
            seismic_alloy_consensus::SeismicTxType::Seismic => {
                let (tx, signature, hash) = TxSeismic::rlp_decode_signed(buf)?.into_parts();
                let signed_tx = Self::new_unhashed(SeismicTypedTransaction::Seismic(tx), signature);
                signed_tx.hash.get_or_init(|| hash);
                Ok(signed_tx)
            }
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        let (transaction, signature) = TxLegacy::rlp_decode_with_signature(buf)?;
        let signed_tx = Self::new_unhashed(SeismicTypedTransaction::Legacy(transaction), signature);

        Ok(signed_tx)
    }
}

impl Transaction for SeismicTransactionSigned {
    fn chain_id(&self) -> Option<u64> {
        self.deref().chain_id()
    }

    fn nonce(&self) -> u64 {
        self.deref().nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.deref().gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.deref().gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.deref().max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.deref().max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.deref().max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.deref().priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.deref().effective_gas_price(base_fee)
    }

    fn effective_tip_per_gas(&self, base_fee: u64) -> Option<u128> {
        self.deref().effective_tip_per_gas(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.deref().is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.deref().kind()
    }

    fn is_create(&self) -> bool {
        self.deref().is_create()
    }

    fn value(&self) -> Uint<256, 4> {
        self.deref().value()
    }

    fn input(&self) -> &Bytes {
        self.deref().input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.deref().access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.deref().blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.deref().authorization_list()
    }
}

impl Typed2718 for SeismicTransactionSigned {
    fn ty(&self) -> u8 {
        self.deref().ty()
    }
}

impl PartialEq for SeismicTransactionSigned {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature &&
            self.transaction == other.transaction &&
            self.tx_hash() == other.tx_hash()
    }
}

impl Hash for SeismicTransactionSigned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature.hash(state);
        self.transaction.hash(state);
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for SeismicTransactionSigned {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let start = buf.as_mut().len();

        // Placeholder for bitflags.
        // The first byte uses 4 bits as flags: IsCompressed[1bit], TxType[2bits], Signature[1bit]
        buf.put_u8(0);

        let sig_bit = self.signature.to_compact(buf) as u8;
        let zstd_bit = self.transaction.input().len() >= 32;

        let tx_bits = if zstd_bit {
            let mut tmp = Vec::with_capacity(256);
            if cfg!(feature = "std") {
                reth_zstd_compressors::TRANSACTION_COMPRESSOR.with(|compressor| {
                    let mut compressor = compressor.borrow_mut();
                    let tx_bits = self.transaction.to_compact(&mut tmp);
                    buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                    tx_bits as u8
                })
            } else {
                let mut compressor = reth_zstd_compressors::create_tx_compressor();
                let tx_bits = self.transaction.to_compact(&mut tmp);
                buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                tx_bits as u8
            }
        } else {
            self.transaction.to_compact(buf) as u8
        };

        // Replace bitflags with the actual values
        buf.as_mut()[start] = sig_bit | (tx_bits << 1) | ((zstd_bit as u8) << 3);

        buf.as_mut().len() - start
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use bytes::Buf;

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

        (Self { signature, transaction, hash: Default::default() }, buf)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for SeismicTransactionSigned {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        #[allow(unused_mut)]
        let mut transaction = SeismicTypedTransaction::arbitrary(u)?;

        let secp = secp256k1::Secp256k1::new();
        let key_pair = secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        let signature = reth_primitives_traits::crypto::secp256k1::sign_message(
            B256::from_slice(&key_pair.secret_bytes()[..]),
            signature_hash(&transaction),
        )
        .unwrap();

        Ok(Self::new_unhashed(transaction, signature))
    }
}

/// Calculates the signing hash for the transaction.
fn signature_hash(tx: &SeismicTypedTransaction) -> B256 {
    match tx {
        SeismicTypedTransaction::Legacy(tx) => tx.signature_hash(),
        SeismicTypedTransaction::Eip2930(tx) => tx.signature_hash(),
        SeismicTypedTransaction::Eip1559(tx) => tx.signature_hash(),
        SeismicTypedTransaction::Eip7702(tx) => tx.signature_hash(),
        SeismicTypedTransaction::Seismic(tx) => tx.signature_hash(),
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
    use seismic_alloy_consensus::serde_bincode_compat::TxSeismic;
    use serde::{Deserialize, Serialize};

    /// Bincode-compatible [`super::SeismicTypedTransaction`] serde implementation.
    #[derive(Debug, Serialize, Deserialize)]
    #[allow(missing_docs)]
    enum SeismicTypedTransaction<'a> {
        Legacy(TxLegacy<'a>),
        Eip2930(TxEip2930<'a>),
        Eip1559(TxEip1559<'a>),
        Eip7702(TxEip7702<'a>),
        Seismic(seismic_alloy_consensus::serde_bincode_compat::TxSeismic<'a>),
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
    use core::str::FromStr;
    use std::io::Read;

    use crate::test_utils::{
        get_signed_seismic_tx, get_signed_seismic_tx_bytes, get_signing_private_key,
    };

    use super::*;
    use alloy_primitives::{aliases::U96, hex, hex::FromHex, PrimitiveSignature, U256};
    use enr::{EnrKey, EnrPublicKey};
    use k256::ecdsa::signature::Keypair;
    use proptest::proptest;
    use proptest_arbitrary_interop::arb;
    use reth_codecs::Compact;
    use secp256k1::{PublicKey, SecretKey};
    use seismic_alloy_consensus::TxSeismicElements;

    #[test]
    fn recover_signer_test() {
        let binding = hex!("0x4af90322821404808504a817c800835b8d808080a1036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e28cffffffffffffffffffffffff80b9029c60806040525f5f8190b150610285806100175f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806324a7f0b71461004357806343bd0d701461005f578063d09de08a1461007d575b5f5ffd5b61005d600480360381019061005891906100f6565b610087565b005b610067610090565b604051610074919061013b565b60405180910390f35b6100856100a7565b005b805f8190b15050565b5f600160025fb06100a19190610181565b14905090565b5f5f81b0809291906100b8906101de565b919050b150565b5f5ffd5b5f819050919050565b6100d5816100c3565b81146100df575f5ffd5b50565b5f813590506100f0816100cc565b92915050565b5f6020828403121561010b5761010a6100bf565b5b5f610118848285016100e2565b91505092915050565b5f8115159050919050565b61013581610121565b82525050565b5f60208201905061014e5f83018461012c565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61018b826100c3565b9150610196836100c3565b9250826101a6576101a5610154565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101e8826100c3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361021a576102196101b1565b5b60018201905091905056fea2646970667358221220ea421d58b6748a9089335034d76eb2f01bceafe3dfac2e57d9d2e766852904df64736f6c63782c302e382e32382d646576656c6f702e323032342e31322e392b636f6d6d69742e39383863313261662e6d6f64005d01a060f71ab574a435b8ab4b34dc70dd823e5ea485ce753054b9688c2fdf63068dbea069d9aac52705455e360ee0e1662737a30ca1c84c3f1a2ddd39d8f84b287d8196").to_vec();
        let mut buf = binding.as_slice();
        let signed_tx = SeismicTransactionSigned::decode_2718(&mut buf).unwrap();

        let encoded_tx = SeismicTransactionSigned::encoded_2718(&signed_tx);
        println!("encoded_tx: {:?}", encoded_tx);
        println!("signed_tx: {:?}", signed_tx);
        println!("orig_tx: {:?}", get_signed_seismic_tx());
        // assert_eq!(encoded_tx, binding);
        assert!(false);

        // let recovered_signer = signed_tx.recover_signer().expect("Failed to recover signer");
        // let expected_signer = Address::from_private_key(&get_signing_private_key());

        // assert_eq!(recovered_signer, expected_signer);
    }

    proptest! {
        #[test]
        fn test_roundtrip_2718(signed_tx in arb::<SeismicTransactionSigned>()) {

            let mut signed_tx_bytes = Vec::<u8>::new();
            signed_tx.encode_2718(&mut signed_tx_bytes);
            let recovered_tx = SeismicTransactionSigned::decode_2718(&mut &signed_tx_bytes[..])
                .expect("Failed to decode transaction");
            assert_eq!(recovered_tx, signed_tx);

        }

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
