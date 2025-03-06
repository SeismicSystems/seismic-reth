# Seismic Reth

[![book](https://github.com/SeismicSystems/seismic-reth/actions/workflows/book.yml/badge.svg?branch=seismic)](https://github.com/SeismicSystems/seismic-reth/actions/workflows/book.yml)
[![CI Status](https://github.com/SeismicSystems/seismic-reth/actions/workflows/seismic.yml/badge.svg?branch=seismic)](https://github.com/SeismicSystems/seismic-reth/actions/workflows/seismic.yml)
[![Chat on Telegram](https://img.shields.io/badge/chat-Join%20Us-blue?logo=telegram)](https://t.me/+jZ6MDPl3tmI1ODE5)

**Encrypted Blockchain Client**

![](./assets/seismic-reth-beta.png)

**[Install](https://seismicsystems.github.io/seismic-reth/installation/installation.html)**
| [User Book](https://seismicsystems.github.io/seismic-reth/)
| [Developer Docs](./docs)
| [Crate Docs](https://seismicsystems.github.io/seismic-reth/docs/)

<!-- [tg-badge]: https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2Fparadigm%5Freth -->

## What is Seismic Reth?

## Goals

Seismic Reth extends [Reth](https://github.com/paradigmxyz/reth) with shielded transaction and storage capabilities, allowing users to confidentially interact with smart contracts and transactions on the Seismic network while maintaining compatibility with existing infrastructure. Seismic Reth runs in a Trusted Execution Environment (TEE) for secure communication between users and the Seismic network.

## Seismic features

See [seismic-features](./seismic-features.md) for a detailed overview of Seismic Reth's new features.

## For Users

See the [Seismic Reth Book](https://seismicsystems.github.io/seismic-reth) for instructions on how to install and run Seismic Reth.

## For Developers

### Building and testing

<!--
When updating this, also update:
- clippy.toml
- Cargo.toml
- .github/workflows/lint.yml
-->

The Minimum Supported Rust Version (MSRV) of this project is [1.82.0](https://blog.rust-lang.org/2024/10/17/Rust-1.82.0.html).

See the book for detailed instructions on how to [build from source](https://seismicsystems.github.io/seismic-reth/installation/source.html).

To fully test Seismic Reth, you will need to have [Geth installed](https://geth.ethereum.org/docs/getting-started/installing-geth), but it is possible to run a subset of tests without Geth.

First, clone the repository:

```sh
git clone https://github.com/SeismicSystems/seismic-reth
cd seismic-reth
```

Next, run the tests:

```sh
# Without Geth
cargo nextest run --workspace

# With Geth
cargo nextest run --workspace --features geth-tests

# With Ethereum Foundation tests
#
# Note: Requires cloning https://github.com/ethereum/tests
#
#   cd testing/ef-tests && git clone https://github.com/ethereum/tests ethereum-tests
cargo nextest run -p ef-tests --features ef-tests
```

> **Note**
>
> Some tests use random number generators to generate test data. If you want to use a deterministic seed, you can set the `SEED` environment variable.

## Getting Help

If you have any questions, first see if the answer to your question can be found in the [book][book].

If the answer is not there:

-   Join the [Telegram][tg-url] to get help, or
-   Open a [discussion](https://github.com/SeismicSystems/seismic-reth/discussions/new) with your question, or
-   Open an issue with [the bug](https://github.com/SeismicSystems/seismic-reth/issues/new?assignees=&labels=C-bug%2CS-needs-triage&projects=&template=bug.yml)

## Security

### Report a Vulnerability

Contact [p@seismic.systems](mailto:p@seismic.systems), [l@seismic.systems](mailto:l@seismic.systems)

## Acknowledgements

Reth is a new implementation of the Ethereum protocol. In the process of developing the node we investigated the design decisions other nodes have made to understand what is done well, what is not, and where we can improve the status quo.

None of this would have been possible without them, so big shoutout to the teams below:

-   [Reth](https://github.com/paradigmxyz/reth): We would like to thank the Rust Ethereum community for their pioneering work in building Ethereum clients in Rust. Their dedication to pushing forward Rust implementations has helped pave the way for projects like Reth.

[book]: https://seismicsystems.github.io/seismic-reth/
[tg-url]: https://t.me/+jZ6MDPl3tmI1ODE5
