//! End-to-end coverage for tx-type RPC classification on the seismic node (precompile variant).
//!
//! The node must run an authenticated signed read as a Seismic tx (type 74) and a plain `eth_call`
//! as standard, and must additionally report `signed_read` only for the former. The probe reads
//! both fields via `staticcall` to the 0x6A tx-context precompile; its `require*()` entry points
//! revert unless the field holds the expected value, so success-vs-revert is a **field-specific**
//! signal that needs no response decryption and exercises the `eth_call` and `estimateGas`
//! handlers directly (reth tags those two handlers independently).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test file.

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex::FromHex, Bytes, TxKind};
use alloy_rpc_types::{Block, TransactionInput, TransactionRequest};
use jsonrpsee::http_client::HttpClientBuilder;
use reth_seismic_node::utils::{
    e2e::{ensure_mock_purpose_keys, setup},
    test_utils::get_signed_seismic_call_typed_data,
};
use reth_seismic_primitives::test_utils::sign_tx;
use reth_seismic_rpc::ext::EthApiOverrideClient;
use seismic_alloy_rpc_types::{SeismicCallRequest, SeismicTransactionRequest};

// TxTypeProbe (stock solc): reads the 0x6A tx-context precompile by staticcall — empty input for
// the tx type (requireSeismic), a single 0x01 byte for the signed-read flag (requireSignedRead /
// requireNotSignedRead). Source + reproduce command: fixtures/TxTypeProbe.sol.
const TXTYPE_PROBE_DEPLOY: &str = "6080604052348015600e575f5ffd5b5061041e8061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610055575f3560e01c806302ce80881461005957806328782220146100775780632dfeb92e146100955780636cac14601461009f578063c6d819f6146100a9575b5f5ffd5b6100616100b3565b60405161006e9190610263565b60405180910390f35b61007f6100c4565b60405161008c9190610263565b60405180910390f35b61009d6100d5565b005b6100a76100e9565b005b6100b16100fe565b005b5f604a6100be610113565b14905090565b5f60016100cf610130565b14905090565b5f6100de610130565b146100e7575f5ffd5b565b60016100f3610130565b146100fc575f5ffd5b565b604a610108610113565b14610111575f5ffd5b565b5f61012b60405180602001604052805f815250610174565b905090565b5f61016f6040518060400160405280600181526020017f0100000000000000000000000000000000000000000000000000000000000000815250610174565b905090565b5f5f5f606a73ffffffffffffffffffffffffffffffffffffffff168460405161019d91906102ce565b5f60405180830381855afa9150503d805f81146101d5576040519150601f19603f3d011682016040523d82523d5f602084013e6101da565b606091505b50915091508180156101ed575060208151145b61022c576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102239061033e565b60405180910390fd5b808060200190518101906102409190610393565b92505050919050565b5f8115159050919050565b61025d81610249565b82525050565b5f6020820190506102765f830184610254565b92915050565b5f81519050919050565b5f81905092915050565b8281835e5f83830152505050565b5f6102a88261027c565b6102b28185610286565b93506102c2818560208601610290565b80840191505092915050565b5f6102d9828461029e565b915081905092915050565b5f82825260208201905092915050565b7f54585f434f4e54455854000000000000000000000000000000000000000000005f82015250565b5f610328600a836102e4565b9150610333826102f4565b602082019050919050565b5f6020820190508181035f8301526103558161031c565b9050919050565b5f5ffd5b5f819050919050565b61037281610360565b811461037c575f5ffd5b50565b5f8151905061038d81610369565b92915050565b5f602082840312156103a8576103a761035c565b5b5f6103b58482850161037f565b9150509291505056fea2646970667358221220e56727fc82b547363957084e7329dccb37dde4880bce06d778cd62d7596e36d064736f6c63782c302e382e33312d646576656c6f702e323032362e372e32302b636f6d6d69742e66643566333839632e6d6f64005d";

const REQUIRE_SEISMIC_SELECTOR: &str = "c6d819f6";
const REQUIRE_SIGNED_READ_SELECTOR: &str = "6cac1460";
const REQUIRE_NOT_SIGNED_READ_SELECTOR: &str = "2dfeb92e";

/// Plain standard `SeismicTransactionRequest` (no signature, no seismic elements) to `contract`.
fn plain_call(contract: alloy_primitives::Address, calldata: Bytes) -> SeismicTransactionRequest {
    SeismicTransactionRequest {
        inner: TransactionRequest {
            to: Some(TxKind::Call(contract)),
            input: TransactionInput { input: Some(calldata), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    }
}

/// The `eth_call` handler must classify a signed read as Seismic (`txtype()==74`) and a plain call
/// as standard: `requireSeismic()` succeeds for the signed read and reverts for the plain call.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_eth_call_classifies_signed_read() {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await.unwrap();
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url()).unwrap();
    let signer = wallet.inner.clone();
    let from = signer.address();
    let chain_id = wallet.chain_id;

    let contract = deploy_probe(&client, &mut node, &signer, from, chain_id).await;
    let recent = node.advance_block().await.unwrap().block().hash();
    let selector = Bytes::from_hex(REQUIRE_SEISMIC_SELECTOR).unwrap();

    // Signed read -> txtype()==74 -> requireSeismic() succeeds.
    let signed = get_signed_seismic_call_typed_data(
        &signer,
        1,
        TxKind::Call(contract),
        chain_id,
        selector.clone(),
        recent,
    )
    .await;
    let signed_res = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicCallRequest::TypedData(signed),
        None,
        None,
        None,
    )
    .await;
    assert!(
        signed_res.is_ok(),
        "signed eth_call to requireSeismic() should succeed (txtype()==74), got {signed_res:?}"
    );

    // Plain eth_call -> txtype()!=74 -> requireSeismic() reverts.
    let plain_res = EthApiOverrideClient::<Block>::call(
        &client,
        SeismicCallRequest::TransactionRequest(plain_call(contract, selector)),
        None,
        None,
        None,
    )
    .await;
    assert!(
        plain_res.is_err(),
        "plain eth_call to requireSeismic() should revert (txtype()!=74), but it succeeded"
    );
}

/// The `estimateGas` handler must classify a signed read as Seismic independently of `eth_call`:
/// estimating `requireSeismic()` succeeds for the signed read and reverts for the plain call.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_estimate_gas_classifies_signed_read() {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await.unwrap();
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url()).unwrap();
    let signer = wallet.inner.clone();
    let from = signer.address();
    let chain_id = wallet.chain_id;

    let contract = deploy_probe(&client, &mut node, &signer, from, chain_id).await;
    let recent = node.advance_block().await.unwrap().block().hash();
    let selector = Bytes::from_hex(REQUIRE_SEISMIC_SELECTOR).unwrap();

    let signed = get_signed_seismic_call_typed_data(
        &signer,
        1,
        TxKind::Call(contract),
        chain_id,
        selector.clone(),
        recent,
    )
    .await;
    let signed_res = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        SeismicCallRequest::TypedData(signed),
        None,
        None,
    )
    .await;
    assert!(
        signed_res.is_ok(),
        "signed estimateGas of requireSeismic() should succeed (txtype()==74), got {signed_res:?}"
    );

    let plain_res = EthApiOverrideClient::<Block>::estimate_gas(
        &client,
        SeismicCallRequest::TransactionRequest(plain_call(contract, selector)),
        None,
        None,
    )
    .await;
    assert!(
        plain_res.is_err(),
        "plain estimateGas of requireSeismic() should revert (txtype()!=74), but it succeeded"
    );
}

/// `signed_read` must be set exactly on the authenticated read path, not merely on anything typed
/// 74: `requireSignedRead()` succeeds for a signed `eth_call` and reverts for a plain one, and
/// `requireNotSignedRead()` does the reverse. Both directions are asserted so the test fails if the
/// flag is hardwired either way.
#[tokio::test(flavor = "multi_thread")]
async fn test_signed_read_flag_eth_call() {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await.unwrap();
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url()).unwrap();
    let signer = wallet.inner.clone();
    let from = signer.address();
    let chain_id = wallet.chain_id;

    let contract = deploy_probe(&client, &mut node, &signer, from, chain_id).await;

    for (selector, signed_should_pass) in
        [(REQUIRE_SIGNED_READ_SELECTOR, true), (REQUIRE_NOT_SIGNED_READ_SELECTOR, false)]
    {
        let recent = node.advance_block().await.unwrap().block().hash();
        let calldata = Bytes::from_hex(selector).unwrap();

        let signed = get_signed_seismic_call_typed_data(
            &signer,
            1,
            TxKind::Call(contract),
            chain_id,
            calldata.clone(),
            recent,
        )
        .await;
        let signed_res = EthApiOverrideClient::<Block>::call(
            &client,
            SeismicCallRequest::TypedData(signed),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            signed_res.is_ok(),
            signed_should_pass,
            "signed eth_call to {selector}: expected pass={signed_should_pass}, got {signed_res:?}"
        );

        let plain_res = EthApiOverrideClient::<Block>::call(
            &client,
            SeismicCallRequest::TransactionRequest(plain_call(contract, calldata)),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            plain_res.is_ok(),
            !signed_should_pass,
            "plain eth_call to {selector}: expected pass={}, got {plain_res:?}",
            !signed_should_pass
        );
    }
}

/// The `estimateGas` handler sets `signed_read` independently of `eth_call` (reth tags the two
/// handlers separately), so it gets its own assertion in both directions.
#[tokio::test(flavor = "multi_thread")]
async fn test_signed_read_flag_estimate_gas() {
    reth_tracing::init_test_tracing();
    ensure_mock_purpose_keys();

    let (mut nodes, _tasks, wallet) = setup(1).await.unwrap();
    let mut node = nodes.pop().unwrap();
    let client = HttpClientBuilder::default().build(node.rpc_url()).unwrap();
    let signer = wallet.inner.clone();
    let from = signer.address();
    let chain_id = wallet.chain_id;

    let contract = deploy_probe(&client, &mut node, &signer, from, chain_id).await;

    for (selector, signed_should_pass) in
        [(REQUIRE_SIGNED_READ_SELECTOR, true), (REQUIRE_NOT_SIGNED_READ_SELECTOR, false)]
    {
        let recent = node.advance_block().await.unwrap().block().hash();
        let calldata = Bytes::from_hex(selector).unwrap();

        let signed = get_signed_seismic_call_typed_data(
            &signer,
            1,
            TxKind::Call(contract),
            chain_id,
            calldata.clone(),
            recent,
        )
        .await;
        let signed_res = EthApiOverrideClient::<Block>::estimate_gas(
            &client,
            SeismicCallRequest::TypedData(signed),
            None,
            None,
        )
        .await;
        assert_eq!(
            signed_res.is_ok(),
            signed_should_pass,
            "signed estimateGas of {selector}: expected pass={signed_should_pass}, got {signed_res:?}"
        );

        let plain_res = EthApiOverrideClient::<Block>::estimate_gas(
            &client,
            SeismicCallRequest::TransactionRequest(plain_call(contract, calldata)),
            None,
            None,
        )
        .await;
        assert_eq!(
            plain_res.is_ok(),
            !signed_should_pass,
            "plain estimateGas of {selector}: expected pass={}, got {plain_res:?}",
            !signed_should_pass
        );
    }
}

/// Deploy the probe as a standard tx via the signer's account (nonce 0) and return its address.
async fn deploy_probe(
    client: &jsonrpsee::http_client::HttpClient,
    node: &mut reth_seismic_node::utils::e2e::SeismicTestNode,
    signer: &alloy_signer_local::PrivateKeySigner,
    from: alloy_primitives::Address,
    chain_id: u64,
) -> alloy_primitives::Address {
    let deploy_code = Bytes::from_hex(TXTYPE_PROBE_DEPLOY).unwrap();
    let deploy = SeismicTransactionRequest {
        inner: TransactionRequest {
            from: Some(from),
            nonce: Some(0),
            to: Some(TxKind::Create),
            gas: Some(1_000_000),
            max_fee_per_gas: Some(20e9 as u128),
            max_priority_fee_per_gas: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(deploy_code), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    };
    let signed = sign_tx(signer.clone(), deploy).await;
    let raw: Bytes = signed.encoded_2718().into();
    EthApiOverrideClient::<Block>::send_raw_transaction(client, raw.into()).await.unwrap();
    node.advance_block().await.unwrap();
    from.create(0)
}
