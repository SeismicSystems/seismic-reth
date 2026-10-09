//! The Seismic chain specification.

use alloy_chains::Chain;
use alloy_eips::eip7840::BlobParams;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, U256};
use alloy_seismic_evm::hardfork::{SeismicHardfork, SeismicHardforks};
use core::fmt::Display;
use reth_chainspec::{
    BaseFeeParams, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork, EthereumHardforks,
    ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_network_peers::NodeRecord;
use reth_primitives_traits::SealedHeader;
use reth_seismic_primitives::SeismicHeader;

/// Seismic chain specification.
///
/// Wraps the stock [`ChainSpec`] and exposes the genesis block as a [`SeismicHeader`], so the node
/// types line up with [`reth_seismic_primitives::SeismicPrimitives`]. The inner spec's sealed
/// genesis header carries the **Seismic** genesis hash (the hash of the Seismic header, which
/// commits to the sub-second timestamp component), so fork ids and filters derived from the inner
/// spec match the chain.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
pub struct SeismicChainSpec {
    /// The stock chain spec. Its `genesis_header` hash is the Seismic genesis hash.
    #[deref]
    inner: ChainSpec,
    /// The Seismic genesis header.
    genesis_header: SealedHeader<SeismicHeader>,
}

impl SeismicChainSpec {
    /// Wraps a stock chain spec, computing the Seismic genesis hash from its genesis header.
    ///
    /// The genesis block has a zero sub-second timestamp component.
    pub fn new(inner: ChainSpec) -> Self {
        let genesis_header =
            SealedHeader::seal_slow(SeismicHeader::from(inner.genesis_header().clone()));
        Self::with_sealed_genesis(inner, genesis_header)
    }

    /// Wraps a stock chain spec with a pre-computed (pinned) Seismic genesis hash.
    ///
    /// The hash is not verified; use the `genesis_header_hash` tests to guard pinned constants.
    pub fn with_genesis_hash(inner: ChainSpec, genesis_hash: B256) -> Self {
        let genesis_header =
            SealedHeader::new(SeismicHeader::from(inner.genesis_header().clone()), genesis_hash);
        Self::with_sealed_genesis(inner, genesis_header)
    }

    fn with_sealed_genesis(
        mut inner: ChainSpec,
        genesis_header: SealedHeader<SeismicHeader>,
    ) -> Self {
        // Re-seal the inner (stock) genesis header with the Seismic hash so everything derived
        // from the inner spec (fork ids, fork filters, `genesis_hash()`) matches the chain.
        inner.genesis_header =
            SealedHeader::new(inner.genesis_header().clone(), genesis_header.hash());
        Self { inner, genesis_header }
    }

    /// Applies `f` to the inner stock spec and re-derives the Seismic genesis header and hash.
    ///
    /// Use this when a test customizes the genesis allocation: mutate `genesis` and recompute
    /// `genesis_header` inside `f`; the Seismic hash (and the inner spec's sealed hash) follow.
    pub fn modify_inner(&mut self, f: impl FnOnce(&mut ChainSpec)) {
        f(&mut self.inner);
        let genesis_header =
            SealedHeader::seal_slow(SeismicHeader::from(self.inner.genesis_header().clone()));
        self.inner.genesis_header =
            SealedHeader::new(self.inner.genesis_header().clone(), genesis_header.hash());
        self.genesis_header = genesis_header;
    }

    /// Converts the given [`Genesis`] into a [`SeismicChainSpec`].
    pub fn from_genesis(genesis: Genesis) -> Self {
        genesis.into()
    }

    /// Returns the inner stock [`ChainSpec`].
    pub const fn inner(&self) -> &ChainSpec {
        &self.inner
    }

    /// Returns the sealed Seismic genesis header.
    pub const fn sealed_genesis_header(&self) -> &SealedHeader<SeismicHeader> {
        &self.genesis_header
    }

    /// Returns the Seismic genesis hash.
    pub fn genesis_hash(&self) -> B256 {
        self.genesis_header.hash()
    }

    /// Returns the Seismic genesis header.
    pub const fn genesis_header(&self) -> &SeismicHeader {
        self.genesis_header.header()
    }
}

impl EthChainSpec for SeismicChainSpec {
    type Header = SeismicHeader;

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        EthChainSpec::base_fee_params_at_timestamp(&self.inner, timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        EthChainSpec::blob_params_at_timestamp(&self.inner, timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        EthChainSpec::deposit_contract(&self.inner)
    }

    fn genesis_hash(&self) -> B256 {
        self.genesis_header.hash()
    }

    fn prune_delete_limit(&self) -> usize {
        EthChainSpec::prune_delete_limit(&self.inner)
    }

    fn display_hardforks(&self) -> Box<dyn Display> {
        EthChainSpec::display_hardforks(&self.inner)
    }

    fn genesis_header(&self) -> &Self::Header {
        self.genesis_header.header()
    }

    fn genesis(&self) -> &Genesis {
        EthChainSpec::genesis(&self.inner)
    }

    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        EthChainSpec::bootnodes(&self.inner)
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        EthChainSpec::final_paris_total_difficulty(&self.inner)
    }

    fn next_block_base_fee(&self, parent: &SeismicHeader, target_timestamp: u64) -> Option<u64> {
        EthChainSpec::next_block_base_fee(&self.inner, &parent.inner, target_timestamp)
    }
}

impl Hardforks for SeismicChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        Hardforks::fork_id(&self.inner, head)
    }

    fn latest_fork_id(&self) -> ForkId {
        Hardforks::latest_fork_id(&self.inner)
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        Hardforks::fork_filter(&self.inner, head)
    }
}

impl EthereumHardforks for SeismicChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.fork(fork)
    }
}

impl SeismicHardforks for SeismicChainSpec {
    fn seismic_fork_activation(&self, fork: SeismicHardfork) -> ForkCondition {
        self.fork(fork)
    }
}

impl EthExecutorSpec for SeismicChainSpec {
    fn deposit_contract_address(&self) -> Option<Address> {
        self.inner.deposit_contract_address()
    }
}

impl From<Genesis> for SeismicChainSpec {
    fn from(genesis: Genesis) -> Self {
        Self::new(ChainSpec::from(genesis))
    }
}

impl From<ChainSpec> for SeismicChainSpec {
    fn from(inner: ChainSpec) -> Self {
        Self::new(inner)
    }
}
