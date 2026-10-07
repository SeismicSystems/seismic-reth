//! Offline, transaction-based fixtures using real SUSDC and `HypERC20` creation bytecode.

use alloy_consensus::{BlockHeader, SignableTransaction, TxLegacy};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{address, hex, keccak256, Address, Bytes, TxKind, B256, U256};
use alloy_rpc_types::Block;
use alloy_rpc_types_engine::PayloadStatus;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall, SolValue};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use reth_chainspec::make_genesis_header;
use reth_e2e_test_utils::wallet::Wallet;
use reth_payload_primitives::PayloadTypes;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use reth_provider::StateProviderFactory;
use reth_seismic_node::{
    engine::SeismicPayloadTypes,
    node::SeismicNode,
    utils::{
        e2e::{
            ensure_mock_purpose_keys, seismic_payload_attributes, test_chain_spec, SeismicTestNode,
        },
        test_utils::get_nonce,
    },
};
use reth_seismic_primitives::{SeismicBlock, SeismicTransactionSigned};
use reth_seismic_rpc::ext::EthApiOverrideClient;
use reth_seismic_test_utils::{get_unsigned_seismic_tx_request, sign_tx};
use reth_tasks::TaskManager;
use seismic_alloy_consensus::GasPayment;
use seismic_revm::gas_token_registry::GAS_TOKEN_REGISTRY;
use std::{sync::Arc, time::Duration};

pub(crate) const TOKEN_PROXY: Address = address!("0x57ab1ed011a20000000000000000000000000000");
pub(crate) const PROXY_ADMIN: Address = address!("0xc4120d2e54b07854ab8b96512fd8eedf3fc415d3");
pub(crate) const IMPLEMENTATION_SLOT: B256 =
    alloy_primitives::b256!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
pub(crate) const GAS_PRICE: u128 = 20_000_000_000;

sol! {
    function addToken(address token, uint256 balanceSlot, uint8 mode, uint8 decimals);
    function activateToken(address token);
    function deactivateToken(address token);
    function transfer(address to, uint256 amount) returns (bool);
    function upgradeAndCall(address proxy, address implementation, bytes data);
    function initialize(address initialAdmin);
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum TokenKind {
    Susdc,
    HypErc20,
}

impl TokenKind {
    pub(crate) const fn decimals(self) -> u8 {
        match self {
            Self::Susdc => 6,
            Self::HypErc20 => 18,
        }
    }
    pub(crate) const fn is_private(self) -> bool {
        matches!(self, Self::Susdc)
    }
    fn artifact(self) -> serde_json::Value {
        serde_json::from_str(match self {
            Self::Susdc => include_str!("fixtures/SUSDC.json"),
            Self::HypErc20 => include_str!("fixtures/HypERC20.json"),
        })
        .unwrap()
    }
    pub(crate) fn balance_slot(self) -> U256 {
        self.artifact().pointer("/balanceMapping/slot").unwrap().as_str().unwrap().parse().unwrap()
    }
}

pub(crate) struct Receipt {
    pub gas_used: U256,
    pub effective_gas_price: U256,
    pub contract_address: Option<Address>,
}

pub(crate) struct TokenTestContext {
    pub node: SeismicTestNode,
    pub client: HttpClient,
    pub wallet: Wallet,
    /// Optional second node that never builds payloads and receives every block produced
    /// by `node` through `engine_newPayload`, so it must execute them itself.
    pub importer: Option<SeismicTestNode>,
    _tasks: TaskManager,
}

impl TokenTestContext {
    pub(crate) async fn new(with_proxy: bool) -> eyre::Result<Self> {
        Self::new_with_importer(with_proxy, false).await
    }

    /// Like [`Self::new`], optionally starting a second node that imports the primary
    /// node's blocks. Locally built payloads are inserted into the builder node's engine
    /// tree as already-executed blocks, so only the importer exercises consensus-import
    /// execution of the produced blocks.
    pub(crate) async fn new_with_importer(
        with_proxy: bool,
        with_importer: bool,
    ) -> eyre::Result<Self> {
        ensure_mock_purpose_keys();
        let mut spec = test_chain_spec();
        if with_proxy {
            // Reuse the genesis proxy, without upgrading it or changing any token
            // storage through a genesis/RPC override. Only its test administrator changes.
            let spec = Arc::make_mut(&mut spec);
            spec.genesis
                .alloc
                .get_mut(&PROXY_ADMIN)
                .unwrap()
                .storage
                .as_mut()
                .unwrap()
                .insert(B256::ZERO, Wallet::default().inner.address().into_word());
            spec.genesis_header =
                SealedHeader::seal_slow(make_genesis_header(&spec.genesis, &spec.hardforks));
        }
        let (mut nodes, tasks, wallet) =
            tokio::spawn(reth_e2e_test_utils::setup_engine::<SeismicNode>(
                if with_importer { 2 } else { 1 },
                spec,
                false,
                Default::default(),
                seismic_payload_attributes,
            ))
            .await??;
        let importer = with_importer.then(|| nodes.pop().unwrap());
        let node = nodes.pop().unwrap();
        let client = HttpClientBuilder::default().build(node.rpc_url())?;
        Ok(Self { node, client, wallet, importer, _tasks: tasks })
    }

    /// Submit a sealed block to `node`'s engine `newPayload` handler and return its status.
    pub(crate) async fn import_block(
        node: &SeismicTestNode,
        block: SealedBlock<SeismicBlock>,
    ) -> eyre::Result<PayloadStatus> {
        let status = tokio::time::timeout(
            Duration::from_secs(30),
            node.inner
                .add_ons_handle
                .beacon_engine_handle
                .new_payload(SeismicPayloadTypes::block_to_payload(block)),
        )
        .await
        .map_err(|_| eyre::eyre!("engine_newPayload timed out"))??;
        Ok(status)
    }

    /// Import the block the builder node just produced into the importer, requiring
    /// `VALID`, and make it canonical there.
    async fn forward_to_importer(&self, block: &SealedBlock<SeismicBlock>) -> eyre::Result<()> {
        let Some(importer) = &self.importer else { return Ok(()) };
        let status = Self::import_block(importer, block.clone()).await?;
        eyre::ensure!(
            status.is_valid(),
            "importer rejected builder block {} ({}): {status:?}",
            block.number(),
            block.hash()
        );
        importer.update_forkchoice(block.parent_hash(), block.hash()).await?;
        Ok(())
    }

    /// Return the initialized node while keeping its task manager available to the caller.
    pub(crate) fn into_parts(self) -> (SeismicTestNode, HttpClient, Wallet, TaskManager) {
        (self.node, self.client, self.wallet, self._tasks)
    }

    /// Submit a raw transaction that the pool must reject; return the RPC error text.
    pub(crate) async fn submit_expect_rejected(&self, raw: Bytes) -> eyre::Result<String> {
        match EthApiOverrideClient::<Block>::send_raw_transaction(&self.client, raw.into()).await {
            Ok(hash) => eyre::bail!("transaction {hash} was accepted but must be rejected"),
            Err(error) => Ok(error.to_string()),
        }
    }

    /// Owner-signed `activateToken` / `deactivateToken`, mined in its own block.
    pub(crate) async fn set_token_active(
        &mut self,
        token: Address,
        active: bool,
    ) -> eyre::Result<Receipt> {
        let input = if active {
            activateTokenCall { token }.abi_encode()
        } else {
            deactivateTokenCall { token }.abi_encode()
        };
        self.native_transaction(TxKind::Call(GAS_TOKEN_REGISTRY), input.into()).await
    }

    /// Submit a raw transaction to the pool without building a block.
    pub(crate) async fn submit(&self, raw: Bytes) -> eyre::Result<B256> {
        Ok(EthApiOverrideClient::<Block>::send_raw_transaction(&self.client, raw.into()).await?)
    }

    /// Build, submit and canonicalize one block from the current pool contents (forwarding
    /// it to the importer when present) and return the sealed block.
    pub(crate) async fn advance(&mut self) -> eyre::Result<SealedBlock<SeismicBlock>> {
        let payload = self.node.advance_block().await?;
        self.forward_to_importer(payload.block()).await?;
        Ok(payload.block().clone())
    }

    /// Fetch a mined transaction's receipt, requiring success.
    pub(crate) async fn receipt(&mut self, hash: B256) -> eyre::Result<Receipt> {
        let receipt: serde_json::Value =
            self.client.request("eth_getTransactionReceipt", rpc_params![hash]).await?;
        eyre::ensure!(
            receipt.get("status").and_then(serde_json::Value::as_str) == Some("0x1"),
            "fixture transaction {hash} failed: {receipt}"
        );
        self.wallet.inner_nonce = get_nonce(&self.client, self.wallet.inner.address()).await;
        Ok(Receipt {
            gas_used: serde_json::from_value(receipt.get("gasUsed").unwrap().clone())?,
            effective_gas_price: serde_json::from_value(
                receipt.get("effectiveGasPrice").unwrap().clone(),
            )?,
            contract_address: serde_json::from_value(
                receipt.get("contractAddress").unwrap().clone(),
            )?,
        })
    }

    pub(crate) async fn mine(&mut self, raw: Bytes) -> eyre::Result<Receipt> {
        let hash = self.submit(raw).await?;
        self.advance().await?;
        self.receipt(hash).await
    }

    /// Sign an owner/wallet legacy transaction at the given gas price without submitting it.
    pub(crate) async fn signed_native_transaction(
        &self,
        to: TxKind,
        input: Bytes,
        gas_price: u128,
    ) -> eyre::Result<Bytes> {
        let tx = TxLegacy {
            chain_id: Some(self.wallet.chain_id),
            nonce: get_nonce(&self.client, self.wallet.inner.address()).await,
            gas_price,
            gas_limit: 6_000_000,
            to,
            input,
            ..Default::default()
        };
        let signature = self.wallet.inner.sign_hash_sync(&tx.signature_hash())?;
        Ok(tx.into_signed(signature).encoded_2718().into())
    }

    pub(crate) async fn native_transaction(
        &mut self,
        to: TxKind,
        input: Bytes,
    ) -> eyre::Result<Receipt> {
        let raw = self.signed_native_transaction(to, input, GAS_PRICE).await?;
        self.mine(raw).await
    }

    pub(crate) async fn recent_hash(&self) -> eyre::Result<B256> {
        let block: serde_json::Value =
            self.client.request("eth_getBlockByNumber", rpc_params!["latest", false]).await?;
        Ok(serde_json::from_value(block.get("hash").unwrap().clone())?)
    }

    /// Sign a Seismic write with the given payment selector at the signer's current nonce,
    /// anchored to the latest block, without submitting it anywhere.
    pub(crate) async fn signed_seismic_transaction(
        &self,
        signer: &PrivateKeySigner,
        to: Address,
        plaintext: Bytes,
        payment: GasPayment,
    ) -> eyre::Result<SeismicTransactionSigned> {
        let mut request = get_unsigned_seismic_tx_request(
            signer,
            get_nonce(&self.client, signer.address()).await,
            TxKind::Call(to),
            self.wallet.chain_id,
            plaintext,
            self.recent_hash().await?,
        )
        .await;
        request.gas_payment = payment;
        let encoded = sign_tx(signer.clone(), request).await.encoded_2718();
        Ok(SeismicTransactionSigned::decode_2718(&mut encoded.as_slice())?)
    }

    pub(crate) async fn seismic_transaction(
        &mut self,
        signer: &PrivateKeySigner,
        to: Address,
        plaintext: Bytes,
        payment: GasPayment,
    ) -> eyre::Result<Receipt> {
        let signed = self.signed_seismic_transaction(signer, to, plaintext, payment).await?;
        self.mine(signed.encoded_2718().into()).await
    }

    pub(crate) async fn bootstrap(
        &mut self,
        kind: TokenKind,
        holder: Address,
        proxy: bool,
    ) -> eyre::Result<TokenFixture> {
        let artifact = kind.artifact();
        let mut creation =
            hex::decode(artifact.pointer("/bytecode/object").unwrap().as_str().unwrap())?;
        if matches!(kind, TokenKind::HypErc20) {
            // This dependency only supplies localDomain(); no bridge behavior is mocked.
            let mailbox = self
                .native_transaction(TxKind::Create, mailbox_creation())
                .await?
                .contract_address
                .unwrap();
            creation.extend(
                (U256::from(kind.decimals()), U256::from(1), U256::from(1), mailbox)
                    .abi_encode_params(),
            );
        }
        let implementation = self
            .native_transaction(TxKind::Create, creation.into())
            .await?
            .contract_address
            .unwrap();
        let amount = U256::from(1_000) * U256::from(10).pow(U256::from(kind.decimals()));
        let initializer: Bytes = match kind {
            TokenKind::Susdc => {
                initializeCall { initialAdmin: self.wallet.inner.address() }.abi_encode().into()
            }
            TokenKind::HypErc20 => {
                let selector = artifact.pointer("/methodIdentifiers/initialize(uint256,string,string,address,address,address)").unwrap()
                    .as_str()
                    .unwrap();
                let mut data = hex::decode(selector)?;
                // The wallet keeps a reserve of the initial supply so tests can fund holders
                // again later through the real transfer path.
                data.extend(
                    (
                        amount * U256::from(10),
                        "Fixture Public Token".to_string(),
                        "FHYP".to_string(),
                        Address::ZERO,
                        Address::ZERO,
                        self.wallet.inner.address(),
                    )
                        .abi_encode_params(),
                );
                data.into()
            }
        };
        let token = if proxy {
            let upgrade =
                upgradeAndCallCall { proxy: TOKEN_PROXY, implementation, data: initializer }
                    .abi_encode();
            self.native_transaction(TxKind::Call(PROXY_ADMIN), upgrade.into()).await?;
            TOKEN_PROXY
        } else {
            if matches!(kind, TokenKind::HypErc20) {
                self.native_transaction(TxKind::Call(implementation), initializer).await?;
            }
            implementation
        };
        let fixture = TokenFixture { token, implementation, kind, funded_amount: amount };
        self.fund(&fixture, holder, amount).await?;
        // Prove the mapping metadata against actual execution, not seeded fixture words.
        assert_eq!(self.token_balance(&fixture, holder)?, (amount, kind.is_private()));
        let registration = addTokenCall {
            token,
            balanceSlot: kind.balance_slot(),
            mode: u8::from(!kind.is_private()),
            decimals: kind.decimals(),
        }
        .abi_encode();
        self.native_transaction(TxKind::Call(GAS_TOKEN_REGISTRY), registration.into()).await?;
        Ok(fixture)
    }

    /// Give `holder` `amount` base units through the token's own code: an admin mint for
    /// SUSDC, a transfer out of the wallet's initial supply for `HypERC20`. Native-funded.
    pub(crate) async fn fund(
        &mut self,
        fixture: &TokenFixture,
        holder: Address,
        amount: U256,
    ) -> eyre::Result<Receipt> {
        match fixture.kind {
            TokenKind::Susdc => {
                // suint256 has a different selector but its ABI word is still 32 bytes.
                let mut mint = hex::decode(
                    fixture
                        .kind
                        .artifact()
                        .pointer("/methodIdentifiers/mint(address,suint256)")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                )?;
                mint.extend((holder, amount).abi_encode_params());
                self.seismic_transaction(
                    &self.wallet.inner.clone(),
                    fixture.token,
                    mint.into(),
                    GasPayment::Native,
                )
                .await
            }
            TokenKind::HypErc20 => {
                let transfer = transferCall { to: holder, amount }.abi_encode();
                self.native_transaction(TxKind::Call(fixture.token), transfer.into()).await
            }
        }
    }

    pub(crate) fn token_balance(
        &self,
        fixture: &TokenFixture,
        holder: Address,
    ) -> eyre::Result<(U256, bool)> {
        fixture.balance_at(&self.node, holder)
    }
}

pub(crate) struct TokenFixture {
    pub token: Address,
    pub implementation: Address,
    pub kind: TokenKind,
    pub funded_amount: U256,
}

impl TokenFixture {
    pub(crate) fn balance_at(
        &self,
        node: &SeismicTestNode,
        holder: Address,
    ) -> eyre::Result<(U256, bool)> {
        let state = node.inner.provider.latest()?;
        Ok(state
            .storage(self.token, self.balance_key(holder))?
            .map_or((U256::ZERO, false), |word| (word.value, word.is_private())))
    }

    pub(crate) fn balance_key(&self, holder: Address) -> B256 {
        keccak256((holder, self.kind.balance_slot()).abi_encode_params())
    }
    pub(crate) fn fee_units(&self, receipt: &Receipt) -> U256 {
        let divisor = U256::from(10).pow(U256::from(18 - self.kind.decimals()));
        (receipt.gas_used * receipt.effective_gas_price + divisor - U256::from(1)) / divisor
    }
}

/// Hand-assembled `localDomain`-only mailbox: return domain 5124, revert all other selectors.
/// The initializer copies the 27-byte runtime; the JUMPI target is its JUMPDEST at offset 17.
fn mailbox_creation() -> Bytes {
    let mut code = hex::decode("601b600c600039601b6000f35f3560e01c63").unwrap();
    code.extend_from_slice(keccak256("localDomain()").get(..4).unwrap());
    code.extend(hex::decode("146011575f5ffd5b6114045f5260205ff3").unwrap());
    code.into()
}
