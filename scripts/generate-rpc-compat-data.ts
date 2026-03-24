/**
 * Generate RPC compatibility test data from a running Seismic testnet.
 *
 * Prerequisites:
 *   1. Summit testnet running: `cd ~/Desktop/Seismic/summit && cargo run --release --bin testnet`
 *   2. Node RPC available at http://localhost:8545
 *
 * Usage:
 *   bun run scripts/generate-rpc-compat-data.ts
 */

import { createWalletClient, createPublicClient, http, defineChain, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const RPC_URL = "http://127.0.0.1:8545";
const OUTPUT_DIR = "crates/rpc/rpc-e2e-tests/testdata/rpc-compat";

// Hardhat account #0 private key (funded in Summit testnet genesis)
const PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

// ssolc-compiled EventEmitter with suint256 private storage
// Events: NumberWasSet(), Ping(uint256 indexed id, bytes32 indexed data)
// Functions: setNumber(suint256) 0x24a7f0b7, emitMultiple(uint256) 0x309818a4, emitEvent(uint256,bytes32) 0x2268e11c
const EVENT_EMITTER_BYTECODE =
  "0x6080604052348015600e575f5ffd5b506101db8061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c80632268e11c1461004357806324a7f0b714610058578063309818a41461006b575b5f5ffd5b610056610051366004610124565b61007e565b005b610056610066366004610144565b6100ae565b610056610079366004610144565b6100dc565b604051819083907f54ce699289354829d667bc6b9d53bf7762254b99c8d6d72c3c4034a85859a4cb905f90a35050565b5f8181b16040517f4bbf2a95b8a1b0106078ab03fae6e70488f9b23dfd9c007e7e9f6058cc55233c9190a150565b60015b818111610120576040517f4bbf2a95b8a1b0106078ab03fae6e70488f9b23dfd9c007e7e9f6058cc55233c905f90a1806101188161015b565b9150506100df565b5050565b5f5f60408385031215610135575f5ffd5b50508035926020909101359150565b5f60208284031215610154575f5ffd5b5035919050565b5f6001820161017857634e487b7160e01b5f52601160045260245ffd5b506001019056fea26469706673582212202b4855662f9dee682b6d4f4c4f0462b829042c0b34ecdf07ffacb796b91ffce164736f6c637828302e382e33312d646576656c6f702e323032362e332e32332b636f6d6d69742e62656261363966340059" as `0x${string}`;

// Raw JSON-RPC helper (for capturing exact request/response pairs)
async function rawRpc(method: string, params: any[] = []): Promise<{ req: any; res: any }> {
  const req = { jsonrpc: "2.0", id: 1, method, params };
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  return { req, res: await res.json() };
}

async function rpc(method: string, params: any[] = []): Promise<any> {
  const { res } = await rawRpc(method, params);
  if (res.error) throw new Error(`RPC error: ${JSON.stringify(res.error)}`);
  return res.result;
}

async function main() {
  console.log("Connecting to Seismic testnet at", RPC_URL);

  const chainId = await rpc("eth_chainId");
  const chainIdNum = parseInt(chainId, 16);
  console.log("Chain ID:", chainId, `(${chainIdNum})`);

  const seismicChain = defineChain({
    id: chainIdNum,
    name: "Seismic Dev",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [RPC_URL] } },
  });

  const account = privateKeyToAccount(PRIVATE_KEY);
  console.log("Using account:", account.address);

  const walletClient = createWalletClient({
    account,
    chain: seismicChain,
    transport: http(RPC_URL),
  });

  const publicClient = createPublicClient({
    chain: seismicChain,
    transport: http(RPC_URL),
  });

  const balance = await publicClient.getBalance({ address: account.address });
  console.log("Balance:", balance / BigInt(1e18), "ETH");

  // Deploy EventEmitter
  console.log("\n--- Deploying EventEmitter contract ---");
  const deployHash = await walletClient.deployContract({
    abi: [],
    bytecode: EVENT_EMITTER_BYTECODE,
    gas: 2_000_000n,
  });
  console.log("Deploy tx:", deployHash);
  const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
  const contractAddr = deployReceipt.contractAddress!;
  console.log("Contract deployed at:", contractAddr, "status:", deployReceipt.status);

  // Tx 1: emitMultiple(10)
  console.log("\n--- Emitting events ---");
  const tx1Hash = await walletClient.sendTransaction({
    to: contractAddr,
    data: ("0x309818a4" + "000000000000000000000000000000000000000000000000000000000000000a") as `0x${string}`,
    gas: 1_000_000n,
  });
  console.log("emitMultiple(10) tx:", tx1Hash);
  const tx1Receipt = await publicClient.waitForTransactionReceipt({ hash: tx1Hash });
  console.log("  status:", tx1Receipt.status, "logs:", tx1Receipt.logs.length);

  // Tx 2: setNumber(42) via CSTORE
  const tx2Hash = await walletClient.sendTransaction({
    to: contractAddr,
    data: ("0x24a7f0b7" + "000000000000000000000000000000000000000000000000000000000000002a") as `0x${string}`,
    gas: 1_000_000n,
  });
  console.log("setNumber(42) tx:", tx2Hash);
  const tx2Receipt = await publicClient.waitForTransactionReceipt({ hash: tx2Hash });
  console.log("  status:", tx2Receipt.status, "logs:", tx2Receipt.logs.length);

  // Tx 3: emitEvent(1, keccak256("test"))
  const tx3Hash = await walletClient.sendTransaction({
    to: contractAddr,
    data: ("0x2268e11c" +
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658") as `0x${string}`,
    gas: 1_000_000n,
  });
  console.log("emitEvent(1, ...) tx:", tx3Hash);
  const tx3Receipt = await publicClient.waitForTransactionReceipt({ hash: tx3Hash });
  console.log("  status:", tx3Receipt.status, "logs:", tx3Receipt.logs.length);

  // Wait for finality
  console.log("\nWaiting for a few more blocks...");
  await Bun.sleep(3000);

  const latestBlock = await rpc("eth_getBlockByNumber", ["latest", false]);
  const headBlockHash = latestBlock.hash;
  const headBlockNumber = latestBlock.number;
  console.log("Head block:", headBlockNumber, `(${parseInt(headBlockNumber, 16)})`, headBlockHash);

  const deployBlock = deployReceipt.blockNumber;
  const tx3Block = tx3Receipt.blockNumber;
  const deployBlockHex = "0x" + deployBlock.toString(16);
  const tx3BlockHex = "0x" + tx3Block.toString(16);

  // -- Capture test data --
  console.log("\n--- Capturing test data ---");

  // 1. genesis.json
  const summitGenesis = await Bun.file(
    `${process.env.HOME}/Desktop/Seismic/summit/testnet/dev.json`
  ).text();
  await Bun.write(`${OUTPUT_DIR}/genesis.json`, summitGenesis);
  console.log("Wrote genesis.json");

  // 2. headfcu.json
  const headfcu = {
    jsonrpc: "2.0",
    id: "fcu45",
    method: "engine_forkchoiceUpdatedV3",
    params: [
      { headBlockHash, safeBlockHash: headBlockHash, finalizedBlockHash: headBlockHash },
      null,
    ],
  };
  await Bun.write(`${OUTPUT_DIR}/headfcu.json`, JSON.stringify(headfcu, null, 2) + "\n");
  console.log("Wrote headfcu.json");

  // 3. forkenv.json
  await Bun.write(`${OUTPUT_DIR}/forkenv.json`, JSON.stringify({
    HIVE_CHAIN_ID: String(chainIdNum),
    HIVE_NETWORK_ID: String(chainIdNum),
  }, null, 2) + "\n");
  console.log("Wrote forkenv.json");

  // 4. eth_syncing
  const { req: syncReq, res: syncRes } = await rawRpc("eth_syncing");
  await Bun.write(
    `${OUTPUT_DIR}/eth_syncing/eth_syncing.io`,
    `// checks client syncing status\n>> ${JSON.stringify(syncReq)}\n<< ${JSON.stringify(syncRes)}\n`
  );
  console.log("Wrote eth_syncing/eth_syncing.io");

  // 5. eth_getLogs
  // 5a. Contract address filter
  const logsReq1Params = [{ address: [contractAddr], fromBlock: deployBlockHex, toBlock: headBlockNumber, topics: null }];
  const { req: logsReq1, res: logsRes1 } = await rawRpc("eth_getLogs", logsReq1Params);
  await Bun.write(
    `${OUTPUT_DIR}/eth_getLogs/contract-addr.io`,
    `// queries for logs from a specific contract across a range of blocks\n>> ${JSON.stringify(logsReq1)}\n<< ${JSON.stringify(logsRes1)}\n`
  );
  const logs1 = logsRes1.result || [];
  console.log(`Wrote eth_getLogs/contract-addr.io (${logs1.length} logs)`);

  // 5b. No topic filter
  const logsReq2Params = [{ address: null, fromBlock: deployBlockHex, toBlock: tx3BlockHex, topics: null }];
  const { req: logsReq2, res: logsRes2 } = await rawRpc("eth_getLogs", logsReq2Params);
  await Bun.write(
    `${OUTPUT_DIR}/eth_getLogs/no-topics.io`,
    `// queries for all logs across a range of blocks\n>> ${JSON.stringify(logsReq2)}\n<< ${JSON.stringify(logsRes2)}\n`
  );
  const logs2 = logsRes2.result || [];
  console.log(`Wrote eth_getLogs/no-topics.io (${logs2.length} logs)`);

  // 5c. Topic exact match
  if (logs1.length > 0) {
    const topic = logs1[0].topics[0];
    const logsReq3Params = [{ address: null, fromBlock: deployBlockHex, toBlock: headBlockNumber, topics: [[topic]] }];
    const { req: logsReq3, res: logsRes3 } = await rawRpc("eth_getLogs", logsReq3Params);
    await Bun.write(
      `${OUTPUT_DIR}/eth_getLogs/topic-exact-match.io`,
      `// queries for logs with a specific topic\n>> ${JSON.stringify(logsReq3)}\n<< ${JSON.stringify(logsRes3)}\n`
    );
    console.log(`Wrote eth_getLogs/topic-exact-match.io (${(logsRes3.result || []).length} logs)`);

    // 5d. Topic wildcard
    const multiTopicLog = logs1.find((l: any) => l.topics.length > 1);
    if (multiTopicLog) {
      const logsReq4Params = [{ address: null, fromBlock: deployBlockHex, toBlock: headBlockNumber, topics: [[], [multiTopicLog.topics[1]]] }];
      const { req: logsReq4, res: logsRes4 } = await rawRpc("eth_getLogs", logsReq4Params);
      await Bun.write(
        `${OUTPUT_DIR}/eth_getLogs/topic-wildcard.io`,
        `// queries for logs with two topics, performing a wildcard match in topic position zero\n>> ${JSON.stringify(logsReq4)}\n<< ${JSON.stringify(logsRes4)}\n`
      );
      console.log(`Wrote eth_getLogs/topic-wildcard.io (${(logsRes4.result || []).length} logs)`);
    }
  }

  // 6. chain.rlp export
  console.log("\n--- chain.rlp export ---");
  const headNum = parseInt(headBlockNumber, 16);
  const rethDataDir = `${process.env.HOME}/Desktop/Seismic/summit/testnet/node0/data/reth_db`;
  const exportCmd = `reth db export-chain ${OUTPUT_DIR}/chain.rlp --datadir ${rethDataDir} --to ${headNum}`;
  console.log("Running:", exportCmd);
  const proc = Bun.spawn(["bash", "-c", exportCmd], { stdout: "inherit", stderr: "inherit" });
  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    console.error(`chain.rlp export failed (exit ${exitCode}). Run manually:\n  ${exportCmd}`);
  } else {
    console.log("Wrote chain.rlp");
  }

  console.log("\n✅ Test data generation complete!");
  console.log("Next steps:");
  console.log("  1. Remove #[ignore] from test_local_rpc_tests_compat");
  console.log("  2. Run: cargo nextest run -p reth-rpc-e2e-tests test_local_rpc_tests_compat");
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});
