#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod fuzz;
mod hardfork_config;
mod integration;
mod ops;
mod p2p;
//mod rpc_compat; // todo: disabling for now we need a more sustainable way to generate state
// roots. Currently broken from stable coin gas update not burning gas
mod testsuite;

const fn main() {}
