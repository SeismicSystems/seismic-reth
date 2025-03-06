# Seismic Reth

[![book](https://github.com/SeismicSystems/seismic-reth/actions/workflows/book.yml/badge.svg?branch=seismic)](https://github.com/SeismicSystems/seismic-reth/actions/workflows/book.yml)
[![CI Status](https://github.com/SeismicSystems/seismic-reth/actions/workflows/seismic.yml/badge.svg?branch=seismic)](https://github.com/SeismicSystems/seismic-reth/actions/workflows/seismic.yml)
[![Chat on Telegram](https://img.shields.io/badge/chat-Join%20Us-blue?logo=telegram)](https://t.me/+xpzfNO4pmRoyM2Ux)

**Privacy-Focused Encrypted Blockchain Client**

![](./assets/seismic-reth-beta.png)

**Quick Links:**
- **[Installation Guide](https://seismicsystems.github.io/seismic-reth/installation/installation.html)**
- **[User Documentation](https://seismicsystems.github.io/seismic-reth/)**
- **[Developer Documentation](./docs)**
- **[API Reference](https://seismicsystems.github.io/seismic-reth/docs/)**

<!-- [tg-badge]: https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2Fparadigm%5Freth -->

## What is Seismic Reth?

Seismic Reth is a privacy-enhanced blockchain client that builds upon the [Reth](https://github.com/paradigmxyz/reth) Ethereum implementation. It provides confidential transaction capabilities while maintaining compatibility with existing blockchain infrastructure. By leveraging Trusted Execution Environments (TEEs), Seismic Reth enables secure and private interactions with smart contracts on the Seismic network.

## Goals and Vision

Seismic Reth extends [Reth](https://github.com/paradigmxyz/reth) with shielded transaction and storage capabilities, allowing users to confidentially interact with smart contracts and transactions on the Seismic network while maintaining compatibility with existing infrastructure. Seismic Reth runs in a Trusted Execution Environment (TEE) for secure communication between users and the Seismic network.

Our primary goals are:

- Provide robust privacy guarantees for blockchain transactions
- Maintain compatibility with existing Ethereum tooling and infrastructure
- Deliver high performance and reliability for production environments
- Create a developer-friendly environment for building privacy-preserving applications

## Seismic Features

Seismic Reth introduces several key privacy-enhancing features:

- **Shielded Transactions**: Confidential transaction processing that protects user privacy
- **Secure Storage**: Encrypted state storage to prevent data leakage
- **TEE Integration**: Leveraging hardware security for enhanced protection
- **Compatibility Layer**: Seamless integration with existing Ethereum tools and applications

For a comprehensive overview of all features, see [seismic-features.md](./seismic-features.md).

## For Users

The [Seismic Reth Book](https://seismicsystems.github.io/seismic-reth) provides comprehensive documentation for users, including:

- Detailed installation instructions
- Configuration guides
- Usage examples
- Troubleshooting tips

Get started by following our [installation guide](https://seismicsystems.github.io/seismic-reth/installation/installation.html).

## For Developers

### Building and Testing

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

### Contributing

We welcome contributions from the community! If you're interested in contributing to Seismic Reth, please:

1. Check our [open issues](https://github.com/SeismicSystems/seismic-reth/issues) for tasks that need attention
2. Read our contribution guidelines (coming soon)
3. Join our [Telegram community][tg-url] to discuss your ideas

## Getting Help

If you have any questions, first see if the answer to your question can be found in the [book][book].

If the answer is not there:

- Join the [Telegram community][tg-url] to get help
- Open a [discussion](https://github.com/SeismicSystems/seismic-reth/discussions/new) with your question
- Open an issue with [the bug](https://github.com/SeismicSystems/seismic-reth/issues/new?assignees=&labels=C-bug%2CS-needs-triage&projects=&template=bug.yml)

## Security

### Report a Vulnerability

If you discover a security vulnerability, please contact us directly:
- Email: [p@seismic.systems](mailto:p@seismic.systems), [l@seismic.systems](mailto:l@seismic.systems)
- Do not disclose the vulnerability publicly until it has been addressed

## Acknowledgements

Reth is a new implementation of the Ethereum protocol. In the process of developing the node we investigated the design decisions other nodes have made to understand what is done well, what is not, and where we can improve the status quo.

None of this would have been possible without them, so big shoutout to the teams below:

- [Reth](https://github.com/paradigmxyz/reth): We would like to thank the Rust Ethereum community for their pioneering work in building Ethereum clients in Rust. Their dedication to pushing forward Rust implementations has helped pave the way for projects like Reth.

## License

Seismic Reth is open-source software licensed under the [MIT License](LICENSE-MIT) and [Apache License 2.0](LICENSE-APACHE).

[book]: https://seismicsystems.github.io/seismic-reth/
[tg-url]: https://t.me/+xpzfNO4pmRoyM2Ux
