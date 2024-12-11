use crate::{Address, Transaction, TransactionSigned, TxKind, U256};
use reth_tee::{decrypt, TeeAPI, TeeError};
use reth_tracing::tracing::debug;
use revm_primitives::{AuthorizationList, Bytes, EVMError, EVMResultGeneric, TxEnv};

#[cfg(all(not(feature = "std"), feature = "optimism"))]
use alloc::vec::Vec;

/// Implements behaviour to fill a [`TxEnv`] from another transaction.
pub trait FillTxEnv<T: TeeAPI> {
    /// Fills [`TxEnv`] with an [`Address`] and transaction.
    fn fill_tx_env(
        &self,
        tx_env: &mut TxEnv,
        sender: Address,
        tee: &T,
    ) -> EVMResultGeneric<(), TeeError>;
}

impl<T: TeeAPI> FillTxEnv<T> for TransactionSigned {
    fn fill_tx_env(
        &self,
        tx_env: &mut TxEnv,
        sender: Address,
        tee: &T,
    ) -> EVMResultGeneric<(), TeeError> {
        #[cfg(feature = "optimism")]
        let envelope = {
            let mut envelope = Vec::with_capacity(self.length_without_header());
            self.encode_enveloped(&mut envelope);
            envelope
        };

        tx_env.caller = sender;
        match self.as_ref() {
            Transaction::Legacy(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.gas_price);
                tx_env.gas_priority_fee = None;
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = tx.chain_id;
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clear();
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
            Transaction::Eip2930(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.gas_price);
                tx_env.gas_priority_fee = None;
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
            Transaction::Eip1559(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.max_fee_per_gas);
                tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
            Transaction::Eip4844(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.max_fee_per_gas);
                tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                tx_env.transact_to = TxKind::Call(tx.to);
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clone_from(&tx.blob_versioned_hashes);
                tx_env.max_fee_per_blob_gas = Some(U256::from(tx.max_fee_per_blob_gas));
                tx_env.authorization_list = None;
            }
            Transaction::Eip7702(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.max_fee_per_gas);
                tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list =
                    Some(AuthorizationList::Signed(tx.authorization_list.clone()));
            }
            #[cfg(feature = "optimism")]
            Transaction::Deposit(tx) => {
                tx_env.access_list.clear();
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::ZERO;
                tx_env.gas_priority_fee = None;
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = None;
                tx_env.nonce = None;
                tx_env.authorization_list = None;

                tx_env.optimism = revm_primitives::OptimismFields {
                    source_hash: Some(tx.source_hash),
                    mint: tx.mint,
                    is_system_transaction: Some(tx.is_system_transaction),
                    enveloped_tx: Some(envelope.into()),
                };
                return;
            }
            Transaction::Seismic(tx) => {
                let msg_sender = self
                    .recover_pubkey()
                    .ok_or(EVMError::Database(TeeError::PublicKeyRecoveryError))?;

                let decrypted_input: Bytes = decrypt(
                    tee,
                    msg_sender,
                    Vec::<u8>::from(tx.input().as_ref()),
                    tx.nonce().clone(),
                )
                .map_err(|e| EVMError::Database(TeeError::DecryptionError(e.to_string())))?
                .into();

                debug!(target: "reth::fill_tx_env", ?decrypted_input, "Encrypted input {:?}", tx.input());

                tx_env.gas_limit = *tx.gas_limit();
                tx_env.gas_price = U256::from(*tx.gas_price());
                tx_env.gas_priority_fee = None;
                tx_env.transact_to = *tx.to();
                tx_env.value = *tx.value();
                tx_env.data = decrypted_input;
                tx_env.chain_id = Some(*tx.chain_id());
                tx_env.nonce = Some(*tx.nonce());
                tx_env.access_list.clear();
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
        }

        #[cfg(feature = "optimism")]
        if !self.is_deposit() {
            tx_env.optimism = revm_primitives::OptimismFields {
                source_hash: None,
                mint: None,
                is_system_transaction: Some(false),
                enveloped_tx: Some(envelope.into()),
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use reth_tee::TeeHttpClient;

    use crate::{Signature, TxSeismic};

    use super::*;

    #[test]
    fn test_fill_tx_env_seismic_invalid_signature() {
        let tx = Transaction::Seismic(TxSeismic::default());
        let signature = Signature::default();
        let tx_signed = TransactionSigned::from_transaction_and_signature(tx, signature);
        let sender = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let tee = TeeHttpClient::default();
        let mut tx_env = TxEnv::default();

        let result = tx_signed.fill_tx_env(&mut tx_env, sender, &tee);

        assert!(matches!(result, Err(EVMError::Custom(err)) if err == "Invalid Signature"));
    }
}
