//! Contains RPC handler implementations specific to state.

use crate::EthApi;
use reth_rpc_convert::RpcConvert;
use reth_rpc_eth_api::{
    helpers::{EthState, LoadPendingBlock, LoadState},
    RpcNodeCore,
};

impl<N, Rpc> EthState for EthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
    Self: LoadPendingBlock,
{
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }

    fn storage_apis_enabled(&self) -> bool {
        self.inner.storage_apis_enabled()
    }
}

impl<N, Rpc> LoadState for EthApi<N, Rpc>
where
    N: RpcNodeCore,
    Rpc: RpcConvert<Primitives = N::Primitives>,
    Self: LoadPendingBlock,
{
}

#[cfg(test)]
mod tests {
    use crate::eth::helpers::types::EthRpcConverter;

    use super::*;
    use alloy_primitives::{Address, StorageKey, U256};
    use reth_chainspec::ChainSpec;
    use reth_evm_ethereum::EthEvmConfig;
    use reth_network_api::noop::NoopNetwork;
    use reth_provider::{
        test_utils::{ExtendedAccount, MockEthProvider, NoopProvider},
        ChainSpecProvider,
    };
    use reth_rpc_eth_api::{helpers::EthState, node::RpcNodeCoreAdapter};
    use reth_transaction_pool::test_utils::{testing_pool, TestPool};
    use std::collections::HashMap;

    use revm::state::FlaggedStorage;

    fn noop_eth_api() -> EthApi<
        RpcNodeCoreAdapter<NoopProvider, TestPool, NoopNetwork, EthEvmConfig>,
        EthRpcConverter<ChainSpec>,
    > {
        let provider = NoopProvider::default();
        let pool = testing_pool();
        let evm_config = EthEvmConfig::mainnet();

        EthApi::builder(provider, pool, NoopNetwork::default(), evm_config)
            .enable_storage_apis(true) // Enable storage APIs for tests
            .build()
    }

    fn mock_eth_api(
        accounts: HashMap<Address, ExtendedAccount>,
    ) -> EthApi<
        RpcNodeCoreAdapter<MockEthProvider, TestPool, NoopNetwork, EthEvmConfig>,
        EthRpcConverter<ChainSpec>,
    > {
        let pool = testing_pool();
        let mock_provider = MockEthProvider::default();

        let evm_config = EthEvmConfig::new(mock_provider.chain_spec());
        mock_provider.extend_accounts(accounts);

        EthApi::builder(mock_provider, pool, NoopNetwork::default(), evm_config)
            .enable_storage_apis(true) // Enable storage APIs for tests
            .build()
    }

    #[tokio::test]
    async fn test_storage() {
        // === Noop ===
        let eth_api = noop_eth_api();
        let address = Address::random();
        let storage = eth_api.storage_at(address, U256::ZERO.into(), None).await.unwrap();
        assert_eq!(storage, U256::ZERO.to_be_bytes());

        // === Mock ===
        let storage_value = FlaggedStorage::public(1337);
        let storage_key = StorageKey::random();
        let storage = HashMap::from([(storage_key, storage_value)]);

        let accounts =
            HashMap::from([(address, ExtendedAccount::new(0, U256::ZERO).extend_storage(storage))]);
        let eth_api = mock_eth_api(accounts);

        let storage_key: U256 = storage_key.into();
        let storage = eth_api.storage_at(address, storage_key.into(), None).await.unwrap();
        assert_eq!(storage, storage_value.value.to_be_bytes());
    }

    #[tokio::test]
    async fn test_flagged_storage() {
        // Noop - should return zero value with is_private = false
        let eth_api = noop_eth_api();
        let address = Address::random();
        let result = eth_api.flagged_storage_at(address, U256::ZERO.into(), None).await.unwrap();
        assert_eq!(result.value, U256::ZERO);
        assert!(!result.is_private);

        // Mock with public storage
        let public_storage_value = FlaggedStorage::new(U256::from(1337), false);
        let storage_key = StorageKey::random();
        let storage = HashMap::from([(storage_key, public_storage_value)]);

        let accounts =
            HashMap::from([(address, ExtendedAccount::new(0, U256::ZERO).extend_storage(storage))]);
        let eth_api = mock_eth_api(accounts);

        let storage_key_u256: U256 = storage_key.into();
        let result =
            eth_api.flagged_storage_at(address, storage_key_u256.into(), None).await.unwrap();

        // Public storage should return the actual value with is_private = false
        assert_eq!(result.value, public_storage_value.value);
        assert!(!result.is_private);

        // Mock with private storage
        let address2 = Address::random();
        let private_storage_value = FlaggedStorage::new(U256::from(9999), true);
        let storage_key2 = StorageKey::random();
        let storage2 = HashMap::from([(storage_key2, private_storage_value)]);

        let accounts2 = HashMap::from([(
            address2,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(storage2),
        )]);
        let eth_api2 = mock_eth_api(accounts2);

        let storage_key2_u256: U256 = storage_key2.into();
        let result2 =
            eth_api2.flagged_storage_at(address2, storage_key2_u256.into(), None).await.unwrap();

        // Private storage should return 0x0 value with is_private = true
        assert_eq!(result2.value, U256::ZERO);
        assert!(result2.is_private);
    }

    #[tokio::test]
    async fn test_get_account_missing() {
        let eth_api = noop_eth_api();
        let address = Address::random();
        let account = eth_api.get_account(address, Default::default()).await.unwrap();
        assert!(account.is_none());
    }

    fn noop_eth_api_storage_disabled() -> EthApi<
        RpcNodeCoreAdapter<NoopProvider, TestPool, NoopNetwork, EthEvmConfig>,
        EthRpcConverter<ChainSpec>,
    > {
        let provider = NoopProvider::default();
        let pool = testing_pool();
        let evm_config = EthEvmConfig::mainnet();

        EthApi::builder(provider, pool, NoopNetwork::default(), evm_config).build()
    }

    #[tokio::test]
    async fn test_storage_disabled() {
        let eth_api = noop_eth_api_storage_disabled();
        let address = Address::random();
        let result = eth_api.storage_at(address, U256::ZERO.into(), None).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Storage APIs are disabled"),
            "Expected error about disabled storage APIs, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_flagged_storage_disabled() {
        let eth_api = noop_eth_api_storage_disabled();
        let address = Address::random();
        let result = eth_api.flagged_storage_at(address, U256::ZERO.into(), None).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Storage APIs are disabled"),
            "Expected error about disabled storage APIs, got: {}",
            err
        );
    }
}
