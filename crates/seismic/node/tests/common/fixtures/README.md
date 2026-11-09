# Real gas-token fixtures

`SUSDC.json` and `HypERC20.json` contain frozen **creation bytecode**, method selectors,
compiler settings/source hashes, and balance-mapping provenance. Tests consume them
with `include_str!`; they do not run Forge, the genesis builder, or download artifacts.
The upstream contracts are not copied or modified by these fixtures.

| Fixture | Upstream source | Compiler | Balance mapping | Decimals | Mode |
| --- | --- | --- | --- | --- | --- |
| SUSDC | `seismic/contracts/src/examples/SUSDC.sol` and its SRC20 base | `0.8.31-develop.2026.3.12+commit.2ebb36d4` | `balances`, root 3 | 6 | Shielded |
| HypERC20 | `hyperlane-monorepo/solidity/contracts/token/HypERC20.sol` | `0.8.33+commit.64118f21` | `_balances`, root 51, offset 0 | constructor configured to 18 | Public |

The SUSDC upstream output did not include compiler storage layout. Its root follows
SRC20's declaration ordering (name, symbol, supply, balances) and is checked against
**actual executed mint/transfer slot values and privacy flags**. HypERC20 includes
its compiler-generated storage layout. These tests verify the registered full-width
root and metadata as committed by the real registry contract.

## Deployment and bootstrap

The direct fixtures clone the embedded dev genesis with test-owned registry and
ProtocolParams, then deploy the real creation bytecode using the native-funded E2E
wallet. SUSDC's constructor initializes its admin and locks implementation
initializers. HypERC20 is initialized by a separate transaction, with 1:1 scale,
zero optional hook/ISM, and the test wallet as owner; its initial supply is minted
to the initializer caller and transferred to the holder.

HypERC20 requires a deployed mailbox. `mailbox_creation()` is a minimal,
hand-assembled test dependency: it returns domain 5124 for `localDomain()` and
reverts for every other selector. It is **not** a Hyperlane bridge simulation.

The proxy test reuses these accounts already embedded in dev genesis:

- Transparent proxy: `0x57ab1ed011a20000000000000000000000000000`.
- ProxyAdmin: `0xc4120d2e54b07854ab8b96512fd8eedf3fc415d3`.

The initial implementation slot is empty. Only the test clone's ProxyAdmin owner
is changed before startup, followed by recomputation of the genesis header. A
signed `upgradeAndCall(proxy, implementation, initialize(wallet))` installs SUSDC
and initializes proxy storage atomically. No implementation or token balance is
injected into genesis or through RPC state overrides.

SUSDC funding uses an encrypted, native-funded call to `mint(address,suint256)`;
its selector is intentionally different from `mint(address,uint256)`. All holders
begin with no native funds. The owner registers the **live token address** (the
proxy address in the proxy case), root, storage mode and decimals after funding.
Tests execute real transfers with signed `Token(address)` payment and a second
transaction using `Auto`. They check exact sender deductions including rounded
fees, recipient balances, token beneficiary rewards, privacy flags, zero native
balance, and untouched implementation balances in the proxy case. Native RPC
inspection uses `eth_getBalance`'s third `true` argument; its default response is a
compatibility mask, not the real native balance. Storage APIs remain disabled by
default; privacy flags are verified through the internal provider snapshot.

## Updating fixtures deliberately

The original upstream artifact SHA-256 is recorded in each JSON. Regeneration is
a development step, never a test prerequisite:

1. Build/obtain the intended upstream artifact with a deliberately selected,
   compatible compiler and settings. Do not assume the installed latest compiler
   generates the same bytecode or shielded opcodes as the frozen artifact.
2. Retain the creation `bytecode`, `methodIdentifiers`, compiler version/settings,
   compilation target, source hashes, and original artifact SHA-256. Retain compiler
   storage layout when supplied; explicitly record how a missing layout was verified.
3. Reverify mapping roots, storage modes, constructor and initializer arguments,
   and immutable decimals. Do not reuse old hardcoded USDC mapping assumptions.
4. Run sequentially against the repository's published dependency pins:

   ```sh
   CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test --locked --offline \
     -p reth-seismic-node --test token_bootstrap -- --test-threads=1
   ```

Historical network genesis files and the committed dev administrative owners are
not changed by fixture deployment. This coverage does not test cross-chain
bridging, proxy upgrades to a second token implementation, or SDK wire parity.
