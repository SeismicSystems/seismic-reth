use reth_rpc_eth_api::{
    helpers::{EthApiSpec, EthBlocks, EthCall, EthFees, EthState, LoadReceipt, Trace},
    FullEthApiTypes,
};

use super::ext::SeismicTransaction;

/// Helper trait to unify all `eth` rpc server building block traits, for simplicity.
///
/// This trait is automatically implemented for any type that implements all the `Eth` traits.
pub trait FullSeismicApi:
    FullEthApiTypes
    + EthApiSpec
    + SeismicTransaction
    + EthBlocks
    + EthState
    + EthCall
    + EthFees
    + Trace
    + LoadReceipt
{
}

impl<T> FullSeismicApi for T where
    T: FullEthApiTypes
        + EthApiSpec
        + SeismicTransaction
        + EthBlocks
        + EthState
        + EthCall
        + EthFees
        + Trace
        + LoadReceipt
{
}
