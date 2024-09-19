use reth::{
    primitives::{revm_primitives::Env, Address, Bytes},
    revm::{inspector_handle_register, Database, Evm, EvmBuilder, GetInspector},
};
use reth_chainspec::{ChainSpec, Head};
use reth_evm::builder::RethEvmBuilder;
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv};
use reth_primitives::{
    revm_primitives::{AnalysisKind, CfgEnvWithHandlerCfg, TxEnv},
    Header, TransactionSigned, U256,
};

use seismic_inspector::get_new_seismic_inspector;

lazy_static::lazy_static! {
    pub static ref SEISMIC_DB: seismic_db::SyncInMemoryDB = seismic_db::SyncInMemoryDB::new();
}

type SeismicExt = seismic_inspector::SeismicInspector<seismic_db::SyncInMemoryDB>;

fn seismic_inspector() -> SeismicExt {
    get_new_seismic_inspector(SEISMIC_DB.clone())
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct SeismicEvmConfig;

impl ConfigureEvm for SeismicEvmConfig {
    type DefaultExternalContext<'a> =
        seismic_inspector::SeismicInspector<seismic_db::SyncInMemoryDB>;

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(seismic_inspector())
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        // pretty sure this won't work but I don't see where this would get called anyway
        RethEvmBuilder::new(db, seismic_inspector()).build_with_inspector(inspector)
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {
        seismic_inspector()
    }
}

impl ConfigureEvmEnv for SeismicEvmConfig {
    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        chain_spec: &ChainSpec,
        header: &Header,
        total_difficulty: U256,
    ) {
        let spec_id = reth_evm_ethereum::revm_spec(
            chain_spec,
            &Head {
                number: header.number,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                total_difficulty,
                hash: Default::default(),
            },
        );

        cfg_env.chain_id = chain_spec.chain().id();
        cfg_env.perf_analyse_created_bytecodes = AnalysisKind::Analyse;
        cfg_env.handler_cfg.spec_id = spec_id;
    }

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        EthEvmConfig::default().fill_tx_env(tx_env, transaction, sender)
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        EthEvmConfig::default().fill_tx_env_system_contract_call(env, caller, contract, data)
    }
}
