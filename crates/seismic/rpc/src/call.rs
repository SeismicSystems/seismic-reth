use futures::Future;
use reth_evm::ConfigureEvmEnv;
use reth_primitives::{revm_primitives::EnvWithHandlerCfg, Bytes};
use reth_revm::{database::StateProviderDatabase, db::CacheDB};
use reth_rpc_eth_api::{
    helpers::{Call, LoadPendingBlock},
    FromEthApiError,
};
use reth_rpc_eth_types::{cache::db::StateProviderTraitObjWrapper, error::ensure_success, utils::recover_raw_transaction};
use reth_rpc_types::BlockId;

/// Seismic call related functions
pub trait SeismicCall: Call + LoadPendingBlock {
    /// Executes the call request (`seismic_call`) and returns the output
    fn call(
        &self,
        request: Bytes,
        block_id: Option<BlockId>,
    ) -> impl Future<Output = Result<Bytes, Self::Error>> + Send {
        async move {
            // `call` must be accompanied with a valid signature.
            let tx = recover_raw_transaction(request.clone())?.into_ecrecovered_transaction();

            let (cfg, block, at) = self.evm_env_at(block_id.unwrap_or_default()).await?;

            let env =
                EnvWithHandlerCfg::new_with_cfg_env(cfg, block, Call::evm_config(self).tx_env(&tx));

            let this = self.clone();

            let (res, _) = self
                .spawn_with_state_at_block(at, move |state| {
                    let db = CacheDB::new(StateProviderDatabase::new(
                        StateProviderTraitObjWrapper(&state),
                    ));
                    this.transact(db, env)
                })
                .await?;

            ensure_success(res.result).map_err(Self::Error::from_eth_err)
        }
    }
}
