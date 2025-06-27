# Seismic Reth Book

_Documentation for Reth users and developers._

Seismic Reth is an **Seismic full node implementation that is focused on being user-friendly, highly modular, as well as being fast and efficient.**

Seismic Reth is production ready, and suitable for usage in mission-critical environments such as staking or high-uptime services. We also actively recommend professional node operators to switch to Reth in production for performance and cost reasons in use cases where high performance with great margins is required such as RPC, MEV, Indexing, Simulations, and P2P activities.

<img src="https://raw.githubusercontent.com/SeismicSystems/seismic-reth/seismic/assets/seismic-reth-beta.png" style="border-radius: 20px">

<!-- Add a quick description about Reth, what it is, the goals of the build, and any other quick overview information   -->

## What is this about?

[Seismic Reth](https://github.com/SeismicSystems/seismic-reth) is an execution layer (EL) implementation that is compatible with all Ethereum consensus layer (CL) implementations that support the [Engine API](https://github.com/ethereum/execution-apis/tree/59e3a719021f48c1ef5653840e3ea5750e6af693/src/engine).

It is originally built and driven forward by [Seismic Systems](https://www.seismic.systems/).

As a full Seismic node, Reth allows users to connect to the Seismic network and interact with the Seismic blockchain.

This includes sending and receiving encrypted transactions, querying logs, as well as accessing and interacting with smart contracts.

Building a successful Seismic node requires creating a high-quality implementation that is both secure and efficient, as well as being easy to use on consumer hardware. It also requires building a strong community of contributors who can help support and improve the software.

## What are the goals of Seismic Reth?

**1. Modularity**

Changes to the upstream Reth is minimized refactoring is continuously pushed to maintain the modularity of the upstream repository

**2. Performance**

Seismic Reth aims to be fast, adding minimal overhead over Reth

## Who is this for?

Seismic Reth is a new Seismic full node that allows users to sync and interact with the entire blockchain, including its historical state if in archive mode.

-   Full node: It can be used as a full node, which stores and processes the entire blockchain, validates blocks and transactions, and participates in the consensus process.
-   Archive node: It can also be used as an archive node, which stores the entire history of the blockchain and is useful for applications that need access to historical data.

As a data engineer/analyst, or as a data indexer, you'll want to use Archive mode. For all other use cases where historical access is not needed, you can use Full mode.

## Is this secure?

To make sure the node is built securely, we run extensive unit and integration tests against Seismic components. Our auditing process is on the way.

## Sections

Here are some useful sections to jump to:

-   Install Seismic Reth by following the [guide](./installation/installation.md).
-   Sync your node on any [official network](./run/run-a-node.md).
-   View [statistics and metrics](./run/observability.md) about your node.
-   Query the [JSON-RPC](./jsonrpc/intro.md) using Foundry's `cast` or `curl`.
-   Set up your [development environment and contribute](./developers/contribute.md)!

> 📖 **About this book**
>
> The book is continuously rendered [here](https://seismicsystems.github.io/seismic-reth/)!
> You can contribute to this book on [GitHub][gh-book].

[gh-book]: https://github.com/SeismicSystems/seismic-reth/tree/seismic/book
