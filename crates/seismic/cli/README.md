# Seismic Reth CLI

The `seismic-reth` binary exposes a deliberately trimmed command set compared
to upstream reth (which also ships `init`, `db`, `p2p`, `dump-genesis`, …):

| command        | purpose                                             |
| -------------- | --------------------------------------------------- |
| `node`         | run the node                                        |
| `stage`        | run individual sync stages (debugging)              |
| `genesis-hash` | print the genesis block hash for `--chain` and exit |

Commands are defined in [`src/lib.rs`](./src/lib.rs).

## `genesis-hash`

```sh
$ seismic-reth genesis-hash --chain crates/seismic/chainspec/res/genesis/dev.json
0x874a74ba374da00d8c097b4be585a60e40f901cac56a764ad0013a07b0a2f93c
```

Offline: computes `keccak(rlp(header))` from the chain spec without touching a
database or booting the node. Stdout is exactly one lowercase `0x`-hex line
(logging is suppressed), so the output can be captured directly by scripts.

Things worth knowing:

- **The hash is a *derived* value, not a file digest.** The genesis header
  contains the state root (a Merkle-trie computation over the entire `alloc`)
  plus fork-dependent fields; no generic hash tool applied to the genesis JSON
  can reproduce it. Only an execution-layer implementation can.
- **It answers with the node's own belief.** The subcommand shares the exact
  `--chain` parse path with `node`, so the printed hash is what a node booted
  from the same `--chain` value computes at genesis.
- **Built-in names echo pinned constants.** `--chain dev`, `--chain testnet`,
  and `--chain mainnet` resolve to built-in chain specs whose genesis hashes
  are pinned in `reth-seismic-chainspec`. To *recompute* a hash — e.g. to
  update a constant after editing a genesis file — pass the JSON file path,
  not the chain name. The `genesis_header_hash` test fails whenever a constant
  drifts from its genesis file, and the constants' doc comments carry the
  exact reproduce commands.

### Why it exists

summit (Seismic's consensus client) embeds `eth_genesis_hash` in its
network-params config, pinning which execution genesis consensus builds on —
and deploy tooling assembles that config **before any node exists**.

Before this subcommand, the hash could only be obtained from a *live* node
(`eth_getBlockByNumber(0)` or startup logs) or copied by hand — leaving stale
hardcoded values undetected until runtime.
