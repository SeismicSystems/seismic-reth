use crate::transaction::TransactionSigned;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng as AesRng},
    Aes256Gcm, Key,
};
use crate::{
    eip7702::SignedAuthorization, keccak256, Bytes, ChainId, Signature, TxKind, TxType, B256, U256, AccessList
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "reth-codec"))]
use reth_codecs::Compact;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(any(test, feature = "reth-codec"), derive(Compact))]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct Seismic {
    /// Added as EIP-155: Simple replay attack protection
    pub chain_id: ChainId,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    pub nonce: u64,
    /// A scalar value equal to the number of
    /// Wei to be paid per unit of gas for all computation
    /// costs incurred as a result of the execution of this transaction; formally Tp.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    pub gas_limit: u64,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    pub max_fee_per_gas: u128,
    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    pub max_priority_fee_per_gas: u128,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    pub to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,
    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: AccessList,
    /// Authorizations are used to temporarily set the code of its signer to
    /// the code referenced by `address`. These also include a `chain_id` (which
    /// can be set to zero and not evaluated) as well as an optional `nonce`.
    pub authorization_list: Vec<SignedAuthorization>,
    /// Input has two uses depending if the transaction `to` field is [`TxKind::Create`] or
    /// [`TxKind::Call`].
    ///
    /// Input as init code, or if `to` is [`TxKind::Create`]: An unlimited size byte array
    /// specifying the EVM-code for the account initialisation procedure `CREATE`
    ///
    /// Input as data, or if `to` is [`TxKind::Call`]: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
    pub ciphertext: Bytes
}

impl Seismic {

    // impl decrypt
}

// pub struct SeismicTransactionSigned {
//     /// Transaction hash
//     pub hash: TxHash,
//     /// The transaction signature values
//     pub signature: Signature,
//     /// encrypted bytes for a vanilla TransactionSigned
//     pub ciphertext: Vec<u8>,
//     // pub transaction: TxType, // This should include the seismic tranaction type
//     pub nonce: u64,
// }

// impl SeismicTransactionSigned {}

// impl SeismicTransactionSigned {
//     pub fn decrypt(&self, key: Key<Aes256Gcm>) -> TransactionSigned {
//         let cipher = Aes256Gcm::new(&key);
//         let nonce = SeismicTransactionSigned::nonce_to_generic_array(self.nonce);
//         /// bytes for a vanilla TransactionSigned in plaintext
//         let mut plaintext = cipher.decrypt(&nonce, self.ciphertext.as_ref()).unwrap();
//         TransactionSigned::decode(&mut plaintext.as_slice())
//             .expect("SeismicTransactionSigned: unable to decode plaintext into TransactionSigned")
//     }

//     pub fn from_transaction_signed(tx: TransactionSigned, key: Key<Aes256Gcm>) -> Self {
//         let mut out = Vec::new();
//         tx.encode(&mut out);

//         let cipher = Aes256Gcm::new(&key);
//         let nonce = SeismicTransactionSigned::nonce_to_generic_array(tx.transaction.nonce());
//         let ciphertext = cipher.encrypt(&nonce, out.as_ref()).unwrap();
//         SeismicTransactionSigned {
//             hash: tx.hash(),
//             signature: tx.signature().clone(),
//             ciphertext: ciphertext,
//             nonce: tx.transaction.nonce(),
//         }
//     }

//     pub fn nonce_to_generic_array(
//         nonce: u64,
//     ) -> GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
//         let mut nonce_bytes = nonce.to_be_bytes().to_vec();


//         let crypto_nonce_size =  GenericArray::<u8, <Aes256Gcm as AeadCore>::NonceSize>::default().len();

//        nonce_bytes.resize(crypto_nonce_size, 0); // pad for crypto

//         let rng = AesRng::default();
//         let libnonce = Aes256Gcm::generate_nonce(rng);
//         println!("libnonce {:?}", libnonce.len());

//         GenericArray::clone_from_slice(&nonce_bytes)

//     }
// }

// pub fn aes_gcm_example() {
//     let rng = AesRng::default();
//     let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);

//     let cipher = Aes256Gcm::new(&key);
//     let nonce = Aes256Gcm::generate_nonce(rng);
//     let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref()).unwrap();
//     let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
//     assert_eq!(&plaintext, b"plaintext message");
//     println!("AES-GCM Encrypted successfully: {:?}", ciphertext);
// }

// #[test]
// fn test_from_seismictransactionsigned_to_transactionsigned() {
//     let encoded_tx_signed_plaintext = hex!("02f872018307910d808507204d2cb1827d0094388c818ca8b9251b393131c08a736a67ccb19297880320d04823e2701c80c001a0cf024f4815304df2867a1a74e9d2707b6abda0337d2d54a4438d453f4160f190a07ac0e6b3bc9395b5b9c8b9e6d77204a236577a5b18467b9175c01de4faa208d9");
//     let orig_tx_signed =
//         TransactionSigned::decode_enveloped(&mut &encoded_tx_signed_plaintext[..]).unwrap();

//     // encrypt it
//     let rng = AesRng::default();
//     let key: Key<Aes256Gcm> = Aes256Gcm::generate_key(rng);
//     let seismic_transaction =
//         SeismicTransactionSigned::from_transaction_signed(orig_tx_signed.clone(), key);

//     assert_eq!(orig_tx_signed.transaction.nonce(), seismic_transaction.nonce);

//     // decrypt it
//     let recovered_tx_signed = SeismicTransactionSigned::decrypt(&seismic_transaction, key);
//     assert!(orig_tx_signed == recovered_tx_signed);
// }
