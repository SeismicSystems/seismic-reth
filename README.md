# Seismic Reth

[![book](https://github.com/SeismicSystems/seismic-reth/actions/workflows/book.yml/badge.svg?branch=seismic)](https://github.com/SeismicSystems/seismic-reth/actions/workflows/book.yml)
[![CI Status](https://github.com/SeismicSystems/seismic-reth/actions/workflows/seismic.yml/badge.svg?branch=seismic)](https://github.com/SeismicSystems/seismic-reth/actions/workflows/seismic.yml)
[![Telegram Chat][tg-badge]][tg-url]

**Encrypted Blockchain Client**

![](./assets/seismic-reth-beta.png)

**[Install](https://seismicsystems.github.io/seismic-reth/installation/installation.html)**
| [User Book](https://seismicsystems.github.io/seismic-reth/)
| [Developer Docs](./docs)
| [Crate Docs](https://seismicsystems.github.io/seismic-reth/docs/)

<!-- [tg-badge]: https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2Fparadigm%5Freth -->

## What is Seismic Reth?

## Goals

Seismic-reth extends [Reth](https://github.com/paradigmxyz/reth) with shielded transaction and storage capabilities, allowing users to confidentially interact with smart contracts and transactions on the Seismic network while maintaining compatibility with existing infrastructure.

## Encrypted Computation

#### Shielded Storage

Seismic Reth provides shielded storage capabilities by

1. Making each storage slot shielded
2. Encrypting data using client private keys and network public keys. The encryption/decryption is handled through a Trusted Execution Environment (TEE) server.

#### Shielded Transaction

Seismic Reth provides shielded transaction capabilities by

1. Providing a new transaction type `TxSeismic` that extends the existing transaction and supports shielded input.
2. Decrypting input and encrypting output through a TEE server

## Seismic features

See [seismic-features.md](./docs/seismic-features.md) for a detailed overview of Seismic Reth's privacy features.

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

Contact [p@seismic.systems](mailto:p@seismic.systems).

## Acknowledgements

Reth is a new implementation of the Ethereum protocol. In the process of developing the node we investigated the design decisions other nodes have made to understand what is done well, what is not, and where we can improve the status quo.

None of this would have been possible without them, so big shoutout to the teams below:

-   [Reth](https://github.com/paradigmxyz/reth): We would like to thank the Rust Ethereum community for their pioneering work in building Ethereum clients in Rust. Their dedication to pushing forward Rust implementations has helped pave the way for projects like Reth.

[book]: https://seismicsystems.github.io/seismic-reth/
[tg-url]: https://t.me/+xpzfNO4pmRoyM2Ux

[tg-badge]: [![Telegram](data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDI0YzYuNjI3IDAgMTItNS4zNzMgMTItMTJTMTguNjI3IDAgMTIgMCAwIDUuMzczIDAgMTJzNS4zNzMgMTIgMTIgMTJaIiBmaWxsPSJ1cmwoI2EpIi8+PHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik01LjQyNSAxMS44NzFhNzk2LjQxNCA3OTYuNDE0IDAgMCAxIDYuOTk0LTMuMDE4YzMuMzI4LTEuMzg4IDQuMDI3LTEuNjI4IDQuNDc3LTEuNjM4LjEgMCAuMzIuMDIuNDcuMTQuMTIuMS4xNS4yMy4xNy4zMy4wMi4xLjA0LjMxLjAyLjQ3LS4xOCAxLjg5OC0uOTYgNi41MDQtMS4zNiA4LjYyMi0uMTcuOS0uNSAxLjE5OS0uODE5IDEuMjI5LS43LjA2LTEuMjI5LS40Ni0xLjg5OC0uOS0xLjA2LS42ODktMS42NDktMS4xMTktMi42NzgtMS43OTgtMS4xOS0uNzgtLjQyLTEuMjA5LjI2LTEuOTA4LjE4LS4xOCAzLjI0Ny0yLjk3OCAzLjMwNy0zLjIyOC4wMS0uMDMuMDEtLjE1LS4wNi0uMjEtLjA3LS4wNi0uMTctLjA0LS4yNS0uMDItLjExLjAyLTEuNzg4IDEuMTQtNS4wNTYgMy4zNDgtLjQ4LjMzLS45MDkuNDktMS4yOTkuNDgtLjQzLS4wMS0xLjI0OC0uMjQtMS44NjgtLjQ0LS43NS0uMjQtMS4zNDktLjM3LTEuMjk5LS43OS4wMy0uMjIuMzMtLjQ0Ljg5LS42NjlaIiBmaWxsPSIjZmZmIi8+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJhIiB4MT0iMTEuOTkiIHkxPSIwIiB4Mj0iMTEuOTkiIHkyPSIyMy44MSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIHN0b3AtY29sb3I9IiMyQUFCRUUiLz48c3RvcCBvZmZzZXQ9IjEiIHN0b3AtY29sb3I9IiMyMjlFRDkiLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48L3N2Zz4K)](https://t.me/+xpzfNO4pmRoyM2Ux)
