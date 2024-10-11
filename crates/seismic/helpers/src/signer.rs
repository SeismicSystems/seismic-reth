use alloy_dyn_abi::TypedData;
use reth_primitives::{
    eip191_hash_message, sign_message, Address, Signature, TransactionSigned, B256,
};
use reth_rpc_eth_api::helpers::{signer::Result, EthSigner};
use reth_rpc_eth_types::SignError;
use reth_rpc_types::TypedTransactionRequest;
use reth_rpc_types_compat::transaction::to_primitive_transaction;
use secp256k1::SecretKey;
use std::collections::HashMap;

/// Holds developer keys
#[derive(Debug, Clone)]
pub struct CustomDevSigner {
    addresses: Vec<Address>,
    accounts: HashMap<Address, SecretKey>,
}

#[async_trait::async_trait]
impl EthSigner for CustomDevSigner {
    fn accounts(&self) -> Vec<Address> {
        self.addresses.clone()
    }

    fn is_signer_for(&self, addr: &Address) -> bool {
        self.accounts.contains_key(addr)
    }

    async fn sign(&self, address: Address, message: &[u8]) -> Result<Signature> {
        // Hash message according to EIP 191:
        // https://ethereum.org/es/developers/docs/apis/json-rpc/#eth_sign
        let hash: reth_primitives::revm_primitives::FixedBytes<32> = eip191_hash_message(message);
        self.sign_hash(hash, address)
    }

    fn sign_transaction(
        &self,
        request: TypedTransactionRequest,
        address: &Address,
    ) -> Result<TransactionSigned> {
        // convert to primitive transaction
        let transaction =
            to_primitive_transaction(request).ok_or(SignError::InvalidTransactionRequest)?;
        let tx_signature_hash = transaction.signature_hash();
        let signature = self.sign_hash(tx_signature_hash, *address)?;

        Ok(TransactionSigned::from_transaction_and_signature(transaction, signature))
    }

    fn sign_typed_data(&self, address: Address, payload: &TypedData) -> Result<Signature> {
        let encoded = payload.eip712_signing_hash().map_err(|_| SignError::InvalidTypedData)?;
        self.sign_hash(encoded, address)
    }
}

impl CustomDevSigner {
    pub fn new(
        secret_keys: &[SecretKey],
        addresses: &[Address],
    ) -> Vec<Box<dyn EthSigner + 'static>> {
        let mut signers = Vec::new();
        for (sk, addr) in secret_keys.iter().zip(addresses.iter()) {
            let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), sk);
            let derived_address = reth_primitives::public_key_to_address(pk);

            if derived_address == *addr {
                let addresses = vec![*addr];
                let accounts = HashMap::from([(*addr, sk.clone())]);
                signers.push(Box::new(Self { addresses, accounts }) as Box<dyn EthSigner>);
            }
        }
        signers
    }

    fn get_key(&self, account: Address) -> Result<&SecretKey> {
        self.accounts.get(&account).ok_or(SignError::NoAccount)
    }

    fn sign_hash(&self, hash: B256, account: Address) -> Result<Signature> {
        let secret = self.get_key(account)?;
        let signature = sign_message(B256::from_slice(secret.as_ref()), hash);
        signature.map_err(|_| SignError::CouldNotSign)
    }
}

/// A trait for adding custom dev signers
pub trait AddCustomDevSigners {
    /// Adds custom dev signers based on provided secret keys and addresses
    fn add_custom_dev_signers(&mut self, secret_keys: &[SecretKey], addresses: &[Address]);
}
