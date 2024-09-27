use alloy_dyn_abi::TypedData;
use reth::{
    providers::BlockReaderIdExt,
    rpc::{
        compat::transaction::from_recovered_with_block_context,
        server_types::eth::{
            utils::recover_raw_transaction, EthApiError, SignError, TransactionSource,
        },
        types::transaction::{
            EIP1559TransactionRequest, EIP2930TransactionRequest, EIP4844TransactionRequest,
            LegacyTransactionRequest,
        },
    },
};
use reth_node_core::{
    primitives::TransactionMeta,
    rpc::eth::helpers::{
        Call, EthApiSpec, EthSigner, LoadBlock, LoadFee, LoadPendingBlock, LoadReceipt,
        LoadTransaction,
    },
};
use reth_primitives::{
    Address, BlockId, Bytes, Receipt, TransactionSigned, TxHash, TxKind, B256, U256,
};
use reth_provider::{ReceiptProvider, TransactionsProvider};
use reth_rpc_eth_api::{FromEthApiError, IntoEthApiError};
use reth_rpc_types::{
    AnyTransactionReceipt, OtherFields, Transaction, TransactionRequest, TypedTransactionRequest,
    WithOtherFields,
};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use seismic_transaction::{
    transaction::{SeismicTransactionBase, SeismicTransactionRequest, SeismicTx},
    types::{SecretData, SeismicTypedTransactionRequest},
};
use std::future::Future;
use tracing::trace;

use super::error::SeismicApiError;

/// Seismic transaction related functions
pub trait SeismicTransactions: LoadTransaction {
    /// Returns a handle for reading data from disk.
    fn provider(&self) -> impl BlockReaderIdExt;

    /// Returns a handle for signing data.
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner>>>;

    /// Returns the transaction by hash.
    fn transaction_by_hash(
        &self,
        hash: B256,
    ) -> impl Future<Output = Result<Option<TransactionSource>, Self::Error>> + Send {
        LoadTransaction::transaction_by_hash(self, hash)
    }

    /// Get all transactions in the block with the given hash.
    fn transactions_by_block(
        &self,
        block: B256,
    ) -> impl Future<Output = Result<Option<Vec<TransactionSigned>>, Self::Error>> + Send {
        async move {
            self.cache().get_block_transactions(block).await.map_err(Self::Error::from_eth_err)
        }
    }

    /// Returns the EIP-2718 encoded transaction by hash.
    fn raw_transaction_by_hash(
        &self,
        hash: B256,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send {
        async move {
            if let Some(tx) =
                self.pool().get_pooled_transaction_element(hash).map(|tx| tx.envelope_encoded())
            {
                return Ok(Some(tx));
            }

            self.spawn_blocking_io(move |ref this| {
                Ok(LoadTransaction::provider(this)
                    .transaction_by_hash(hash)
                    .map_err(Self::Error::from_eth_err)?
                    .map(|tx| tx.envelope_encoded()))
            })
            .await
        }
    }

    /// Returns the _historical_ transaction and the block it was mined in
    fn historical_transaction_by_hash_at(
        &self,
        hash: B256,
    ) -> impl Future<Output = Result<Option<(TransactionSource, B256)>, Self::Error>> + Send {
        async move {
            match self.transaction_by_hash_at(hash).await? {
                None => Ok(None),
                Some((tx, at)) => Ok(at.as_block_hash().map(|hash| (tx, hash))),
            }
        }
    }

    /// Returns the transaction receipt for the given hash.
    fn transaction_receipt(
        &self,
        hash: B256,
    ) -> impl Future<Output = Result<Option<AnyTransactionReceipt>, Self::Error>> + Send
    where
        Self: LoadReceipt + 'static,
    {
        async move {
            match self.load_transaction_and_receipt(hash).await? {
                Some((tx, meta, receipt)) => {
                    self.build_transaction_receipt(tx, meta, receipt).await.map(Some)
                }
                None => Ok(None),
            }
        }
    }

    /// Helper method that loads a transaction and its receipt.
    fn load_transaction_and_receipt(
        &self,
        hash: TxHash,
    ) -> impl Future<
        Output = Result<Option<(TransactionSigned, TransactionMeta, Receipt)>, Self::Error>,
    > + Send
    where
        Self: 'static,
    {
        let this = self.clone();
        self.spawn_blocking_io(move |_| {
            let (tx, meta) = match LoadTransaction::provider(&this)
                .transaction_by_hash_with_meta(hash)
                .map_err(Self::Error::from_eth_err)?
            {
                Some((tx, meta)) => (tx, meta),
                None => return Ok(None),
            };

            let receipt = match SeismicTransactions::provider(&this)
                .receipt_by_hash(hash)
                .map_err(Self::Error::from_eth_err)?
            {
                Some(recpt) => recpt,
                None => return Ok(None),
            };

            Ok(Some((tx, meta, receipt)))
        })
    }

    /// Get [`Transaction`] by [`BlockId`] and index of transaction within that block.
    ///
    /// Returns `Ok(None)` if the block does not exist, or index is out of range.
    fn transaction_by_block_and_tx_index(
        &self,
        block_id: BlockId,
        index: usize,
    ) -> impl Future<Output = Result<Option<Transaction>, Self::Error>> + Send
    where
        Self: LoadBlock,
    {
        async move {
            if let Some(block) = self.block_with_senders(block_id).await? {
                let block_hash = block.hash();
                let block_number = block.number;
                let base_fee_per_gas = block.base_fee_per_gas;
                if let Some(tx) = block.into_transactions_ecrecovered().nth(index) {
                    return Ok(Some(from_recovered_with_block_context(
                        tx,
                        block_hash,
                        block_number,
                        base_fee_per_gas,
                        index,
                    )));
                }
            }

            Ok(None)
        }
    }

    /// Get transaction, as raw bytes, by [`BlockId`] and index of transaction within that block.
    fn raw_transaction_by_block_and_tx_index(
        &self,
        block_id: BlockId,
        index: usize,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send
    where
        Self: LoadBlock,
    {
        async move {
            if let Some(block) = self.block_with_senders(block_id).await? {
                if let Some(tx) = block.transactions().nth(index) {
                    return Ok(Some(tx.envelope_encoded()));
                }
            }

            Ok(None)
        }
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    fn send_raw_transaction(
        &self,
        tx: Bytes,
    ) -> impl Future<Output = Result<B256, Self::Error>> + Send {
        async move {
            let recovered = recover_raw_transaction(tx.clone())?;
            let pool_transaction =
                <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);

            let hash = self
                .pool()
                .add_transaction(TransactionOrigin::Local, pool_transaction)
                .await
                .map_err(Self::Error::from_eth_err)?;

            Ok(hash)
        }
    }

    /// Signs transaction with a matching signer, if any and submits the transaction to the pool.
    fn send_transaction(
        &self,
        mut request: WithOtherFields<TransactionRequest>,
    ) -> impl Future<Output = Result<B256, Self::Error>> + Send
    where
        Self: EthApiSpec + LoadBlock + LoadPendingBlock + LoadFee + Call,
    {
        async move {
            let from = match request.from {
                Some(from) => from,
                None => return Err(SignError::NoAccount.into_eth_err()),
            };
            if self.find_signer(&from).is_err() {
                return Err(SignError::NoAccount.into_eth_err());
            }
            if request.nonce.is_none() {
                let nonce = self.transaction_count(from, Some(BlockId::pending())).await?;
                request.nonce = Some(u64::try_from(nonce).unwrap());
            }

            let (nonce, _) = self.request_nonce(&request, from).await?;

            let request = self.build_typed_tx_request(request, nonce).await?;

            if let SeismicTypedTransactionRequest::Seismic(seismic_data) = &request {
                let mut db = SEISMIC_DB.clone();
                println!(
                    "Detected Seismic transaction with {} preimages",
                    seismic_data.secret_data.len()
                );
                let signed_tx = self.sign_request(&from, request)?;
                let recovered =
                    signed_tx.into_ecrecovered().ok_or(EthApiError::InvalidTransactionSignature)?;

                let pool_transaction = match recovered.try_into() {
                    Ok(converted) => converted,
                    Err(_) => return Err(EthApiError::TransactionConversionError.into()),
                };

                // submit the transaction to the pool with a `Local` origin
                let hash = LoadTransaction::pool(self)
                    .add_transaction(TransactionOrigin::Local, pool_transaction)
                    .await
                    .map_err(Self::Error::from_eth_err)?;

                Ok(hash)
            }
        }
    }

    /// Signs a transaction, with configured signers.
    fn sign_request(
        &self,
        from: &Address,
        request: SeismicTypedTransactionRequest,
    ) -> Result<TransactionSigned, Self::Error> {
        for signer in self.signers().read().iter() {
            if signer.is_signer_for(from) {
                let request_for_signing = build_request_for_signing(request);
                return match signer.sign_transaction(request_for_signing, from) {
                    Ok(tx) => Ok(tx),
                    Err(e) => Err(e.into_eth_err()),
                };
            }
        }
        Err(EthApiError::InvalidTransactionSignature.into())
    }

    /// Signs given message. Returns the signature.
    fn sign(
        &self,
        account: Address,
        message: Bytes,
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + Send {
        async move {
            Ok(self
                .find_signer(&account)?
                .sign(account, &message)
                .await
                .map_err(Self::Error::from_eth_err)?
                .to_hex_bytes())
        }
    }

    /// Encodes and signs the typed data according EIP-712. Payload must implement Eip712 trait.
    fn sign_typed_data(&self, data: &TypedData, account: Address) -> Result<Bytes, Self::Error> {
        Ok(self
            .find_signer(&account)?
            .sign_typed_data(account, data)
            .map_err(Self::Error::from_eth_err)?
            .to_hex_bytes())
    }

    /// Returns the signer for the given account, if found in configured signers.
    fn find_signer(
        &self,
        account: &Address,
    ) -> Result<Box<(dyn EthSigner + 'static)>, Self::Error> {
        self.signers()
            .read()
            .iter()
            .find(|signer| signer.is_signer_for(account))
            .map(|signer| dyn_clone::clone_box(&**signer))
            .ok_or_else(|| SignError::NoAccount.into_eth_err())
    }

    /// Returns the nonce for this request
    ///
    /// This returns a tuple of `(request nonce, highest nonce)`
    /// If the nonce field of the `request` is `None` then the tuple will be `(highest nonce,
    /// highest nonce)`.
    ///
    /// This will also check the tx pool for pending transactions from the sender.
    fn request_nonce<'a>(
        &'a self,
        request: &'a TransactionRequest,
        from: Address,
    ) -> impl Future<Output = Result<(u64, u64), Self::Error>> + Send + 'a
    where
        Self: EthApiSpec + LoadBlock + LoadPendingBlock + LoadFee + Call + Send + Sync,
    {
        async move {
            let highest_nonce = self.transaction_count(from, Some(BlockId::pending())).await?;
            let nonce = request.nonce.unwrap_or(u64::try_from(highest_nonce).unwrap());
            Ok((nonce, u64::try_from(highest_nonce).unwrap()))
        }
    }

    /// Recognizes the transaction request and builds the typed transaction request.
    fn build_typed_tx_request(
        &self,
        request: WithOtherFields<TransactionRequest>,
        nonce: u64,
    ) -> impl Future<Output = Result<SeismicTypedTransactionRequest, Self::Error>> + Send
    where
        Self: EthApiSpec + LoadBlock + LoadPendingBlock + LoadFee + Call,
    {
        async move {
            let chain_id = self.chain_id();
            // let request_without_other_fields = separate_other_fields(&request);
            // let estimated_gas = self
            //     .estimate_gas_at( -- buggy for now
            //         request_without_other_fields.clone(),
            //         BlockId::pending(),
            //         None,
            //     ) // todo: make into TransactionRequest and send to sign
            //     .await?;
            let gas_limit = U256::from(request.gas.unwrap_or_default());
            let max_fee_per_gas = request.max_fee_per_gas;
            let max_priority_fee_per_gas = request.max_priority_fee_per_gas;
            let max_fee_per_blob_gas = request.max_fee_per_blob_gas;
            let gas_price = request.gas_price;
            let request = match transaction_request_to_seismic_typed(request) {
                Some(SeismicTypedTransactionRequest::Legacy(mut req)) => {
                    req.chain_id = Some(chain_id.to());
                    req.gas_limit = gas_limit.saturating_to();
                    req.gas_price = self.legacy_gas_price(gas_price.map(U256::from)).await?;
                    SeismicTypedTransactionRequest::Legacy(req)
                }
                Some(SeismicTypedTransactionRequest::EIP2930(mut req)) => {
                    req.chain_id = chain_id.to();
                    req.gas_limit = gas_limit.saturating_to();
                    req.gas_price = self.legacy_gas_price(gas_price.map(U256::from)).await?;
                    SeismicTypedTransactionRequest::EIP2930(req)
                }
                Some(SeismicTypedTransactionRequest::EIP1559(mut req)) => {
                    // let (max_fee_per_gas, max_priority_fee_per_gas) = self
                    //     .eip1559_fees(
                    //         max_fee_per_gas.map(U256::from),
                    //         max_priority_fee_per_gas.map(U256::from),
                    //     )
                    //     .await?;
                    let (max_fee_per_gas, max_priority_fee_per_gas) =
                        (U256::from(210000), U256::from(0));
                    req.chain_id = chain_id.to();
                    req.gas_limit = gas_limit.saturating_to();
                    req.max_fee_per_gas = max_fee_per_gas.saturating_to();
                    req.max_priority_fee_per_gas = max_priority_fee_per_gas.saturating_to();
                    SeismicTypedTransactionRequest::EIP1559(req)
                }
                Some(SeismicTypedTransactionRequest::EIP4844(mut req)) => {
                    let (max_fee_per_gas, max_priority_fee_per_gas) = self
                        .eip1559_fees(
                            max_fee_per_gas.map(U256::from),
                            max_priority_fee_per_gas.map(U256::from),
                        )
                        .await?;
                    req.max_fee_per_gas = max_fee_per_gas;
                    req.max_priority_fee_per_gas = max_priority_fee_per_gas;
                    req.max_fee_per_blob_gas =
                        self.eip4844_blob_fee(max_fee_per_blob_gas.map(U256::from)).await?;
                    req.chain_id = chain_id.to();
                    req.gas_limit = gas_limit;
                    SeismicTypedTransactionRequest::EIP4844(req)
                }
                Some(SeismicTypedTransactionRequest::Seismic(mut m)) => {
                    m.base_mut().nonce = nonce;
                    m.base_mut().chain_id = chain_id.to();
                    m.base_mut().gas_limit = u128::try_from(gas_limit).unwrap();
                    if max_fee_per_gas.is_none() {
                        m.base_mut().max_fee_per_gas = 210000;
                    }
                    SeismicTypedTransactionRequest::Seismic(m)
                }

                None => {
                    return Err(Self::Error::from(SeismicApiError::FailedToDecodeTransaction.into()))
                }
            };

            Ok(request)
        }
    }
}

pub fn transaction_request_to_seismic_typed(
    tx: WithOtherFields<TransactionRequest>,
) -> Option<SeismicTypedTransactionRequest> {
    let WithOtherFields::<TransactionRequest> {
        inner:
            TransactionRequest {
                from: _,
                to,
                gas_price,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                max_fee_per_blob_gas,
                blob_versioned_hashes,
                gas,
                value,
                input,
                nonce,
                mut access_list,
                sidecar,
                transaction_type,
                ..
            },
        other,
    } = tx;

    if transaction_type == Some(0x64) && has_seismic_fields(&other) {
        return Some(SeismicTypedTransactionRequest::Seismic(SeismicTransactionRequest {
            base: SeismicTransactionBase {
                nonce: nonce.unwrap_or_default(),
                max_fee_per_gas: max_fee_per_gas.unwrap_or_default(),
                max_priority_fee_per_gas: max_priority_fee_per_gas.unwrap_or_default(),
                gas_limit: gas.unwrap_or_default(),
                value: value.unwrap_or(U256::ZERO),
                input: input.into_input().unwrap_or_default(),
                to: to.unwrap_or_default(),
                chain_id: 0,
                access_list: access_list.unwrap_or_default(),
            },
            secret_data: other.get_deserialized::<Vec<SecretData>>("secretData")?.ok()?,
        }));
    }

    match (
        gas_price,
        max_fee_per_gas,
        access_list.take(),
        max_fee_per_blob_gas,
        blob_versioned_hashes,
        sidecar,
    ) {
        // legacy transaction
        (Some(_), None, None, None, None, None) => {
            Some(SeismicTypedTransactionRequest::Legacy(LegacyTransactionRequest {
                nonce: nonce.unwrap_or_default(),
                gas_price: U256::from(gas_price.unwrap_or_default()),
                gas_limit: U256::from(gas.unwrap_or_default()),
                value: value.unwrap_or_default(),
                input: input.into_input().unwrap_or_default(),
                kind: to.unwrap_or(TxKind::Create),
                chain_id: None,
            }))
        }
        // EIP2930
        (_, None, Some(access_list), None, None, None) => {
            Some(SeismicTypedTransactionRequest::EIP2930(EIP2930TransactionRequest {
                nonce: nonce.unwrap_or_default(),
                gas_price: U256::from(gas_price.unwrap_or_default()),
                gas_limit: U256::from(gas.unwrap_or_default()),
                value: value.unwrap_or_default(),
                input: input.into_input().unwrap_or_default(),
                kind: to.unwrap_or(TxKind::Create),
                chain_id: 0,
                access_list,
            }))
        }
        // EIP1559
        (None, _, _, None, None, None) => {
            Some(SeismicTypedTransactionRequest::EIP1559(EIP1559TransactionRequest {
                nonce: nonce.unwrap_or_default(),
                max_fee_per_gas: U256::from(max_fee_per_gas.unwrap_or_default()),
                max_priority_fee_per_gas: U256::from(max_priority_fee_per_gas.unwrap_or_default()),
                gas_limit: U256::from(gas.unwrap_or_default()),
                value: value.unwrap_or_default(),
                input: input.into_input().unwrap_or_default(),
                kind: to.unwrap_or(TxKind::Create),
                chain_id: 0,
                access_list: access_list.unwrap_or_default(),
            }))
        }
        // EIP4844
        (None, _, _, Some(max_fee_per_blob_gas), Some(blob_versioned_hashes), Some(sidecar)) => {
            Some(SeismicTypedTransactionRequest::EIP4844(EIP4844TransactionRequest {
                chain_id: 0,
                nonce: nonce.unwrap_or_default(),
                max_priority_fee_per_gas: U256::from(max_priority_fee_per_gas.unwrap_or_default()),
                max_fee_per_gas: U256::from(max_fee_per_gas.unwrap_or_default()),
                gas_limit: U256::from(gas.unwrap_or_default()),
                value: value.unwrap_or_default(),
                input: input.into_input().unwrap_or_default(),
                to: match to {
                    Some(TxKind::Call(to)) => to,
                    _ => Address::default(),
                },
                access_list: access_list.unwrap_or_default(),
                max_fee_per_blob_gas: U256::from(max_fee_per_blob_gas),
                blob_versioned_hashes,
                sidecar,
            }))
        }
        _ => None,
    }
}

pub fn has_seismic_fields(other: &OtherFields) -> bool {
    other.contains_key("secretData")
}

pub fn separate_other_fields(tx: &WithOtherFields<TransactionRequest>) -> &TransactionRequest {
    &tx.inner
}

pub fn build_request_for_signing(
    request: SeismicTypedTransactionRequest,
) -> TypedTransactionRequest {
    match request {
        SeismicTypedTransactionRequest::Legacy(tx) => TypedTransactionRequest::Legacy(tx),
        SeismicTypedTransactionRequest::EIP2930(tx) => TypedTransactionRequest::EIP2930(tx),
        SeismicTypedTransactionRequest::EIP1559(tx) => TypedTransactionRequest::EIP1559(tx),
        SeismicTypedTransactionRequest::EIP4844(tx) => TypedTransactionRequest::EIP4844(tx),
        SeismicTypedTransactionRequest::Seismic(seismic_tx) => {
            let eip1559_tx = EIP1559TransactionRequest {
                nonce: seismic_tx.base().nonce,
                max_fee_per_gas: U256::try_from(seismic_tx.base().max_fee_per_gas).unwrap(),
                max_priority_fee_per_gas: U256::try_from(
                    seismic_tx.base().max_priority_fee_per_gas,
                )
                .unwrap(),
                gas_limit: U256::try_from(seismic_tx.base().gas_limit).unwrap(),
                value: seismic_tx.base().value,
                input: seismic_tx.base().input.clone(),
                kind: seismic_tx.base().to,
                chain_id: seismic_tx.base().chain_id,
                access_list: seismic_tx.base().access_list.clone(),
            };
            TypedTransactionRequest::EIP1559(eip1559_tx)
        }
    }
}
