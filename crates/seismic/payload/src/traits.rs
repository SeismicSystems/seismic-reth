use alloy_consensus::{BlockBody, Header};
use reth_primitives_traits::{NodePrimitives, SignedTransaction};
use reth_seismic_primitives::{transaction::signed::OpTransaction, DepositReceipt};

/// Helper trait to encapsulate common bounds on [`NodePrimitives`] for OP payload builder.
pub trait SeismicPayloadPrimitives:
    NodePrimitives<
    Receipt: DepositReceipt,
    SignedTx = Self::_TX,
    BlockHeader = Header,
    BlockBody = BlockBody<Self::_TX>,
>
{
    /// Helper AT to bound [`NodePrimitives::Block`] type without causing bound cycle.
    type _TX: SignedTransaction + OpTransaction;
}

impl<Tx, T> SeismicPayloadPrimitives for T
where
    Tx: SignedTransaction + OpTransaction,
    T: NodePrimitives<
        SignedTx = Tx,
        Receipt: DepositReceipt,
        BlockHeader = Header,
        BlockBody = BlockBody<Tx>,
    >,
{
    type _TX = Tx;
}
