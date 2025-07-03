import { encodeFunctionData, http, parseEther, stringToBytes, stringToHex, type Chain } from "viem";
import {
    AesGcmCrypto,
    createShieldedWalletClient,
    localSeismicDevnet,
    randomEncryptionNonce,
    signSeismicTxTypedData,
} from "seismic-viem";
import { privateKeyToAccount } from "viem/accounts";
import { beforeAll, afterAll, describe, test, expect } from "bun:test";
import {
    setupNode,
    testAesKeygen,
    testAesGcm,
    testEcdh,
    testHkdfHex,
    testHkdfString,
    testRng,
    testRngWithPers,
    testSecp256k1,
    testSeismicCallTypedData,
    testSeismicTx,
    testSeismicTxEncoding,
    testSeismicTxTypedData,
    testSeismicTxTrace,
    testWsConnection,
    buildNode,
    testLegacyTxTrace,
} from "seismic-viem-tests";

const TIMEOUT_MS = 20_000;
const chain = localSeismicDevnet;
const port = 8545;

const TEST_ACCOUNT_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(TEST_ACCOUNT_PRIVATE_KEY);
const encryptionSk =
    "0x311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505";
const encryptionPubkey =
    "0x028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0";

const HOST = "node-4.seismicdev.net";

let url: string = `https://${HOST}/rpc`;
let wsUrl: string = `wss://${HOST}/ws`;
let exitProcess: () => Promise<void> = async () => {
    process.exit(0);
};
let pcParams: { chain: Chain; url: string };

beforeAll(async () => {
    /*
    await buildNode(chain);
    const debug = false;
    const rethArgs = debug
        ? { port, ws: true, silent: false, verbosity: 4 }
        : { port, ws: true };

    const node = await setupNode(chain, rethArgs);
    pcParams = { chain, url: node.url };
    exitProcess = node.exitProcess;
    url = node.url;
    wsUrl = `ws://localhost:${port}`;
    */
});

describe("Moonhatch seismic tx", async () => {
    const client = await createShieldedWalletClient({
        chain,
        account,
        transport: http(url),
        encryptionSk,
    });

    const plaintext = encodeFunctionData({
        abi: [
            {
                type: "function",
                name: "buy",
                inputs: [
                    {
                        name: "coinId",
                        type: "uint32",
                        internalType: "uint32",
                    },
                ],
                outputs: [
                    {
                        name: "weiRefunded",
                        type: "uint256",
                        internalType: "uint256",
                    },
                ],
                stateMutability: "payable",
            },
        ],
        functionName: "buy",
        args: [56249],
    });
    console.log(await client.getTeePublicKey())
    const aesKey = client.getEncryption()
    console.log(`AES Key: ${aesKey}`)
    const aesCipher = new AesGcmCrypto(aesKey)
    const encryptionNonce = "0x7da3a99bf0f90d56551d99ea"
    const encrypted = await aesCipher.encrypt(plaintext, encryptionNonce)
    const nonce = await client.getTransactionCount({ address: account.address })

    console.log(encrypted)
    console.log(encryptionNonce)
    console.log(plaintext);
    const { typedData, signature } = await signSeismicTxTypedData(client, {
        chainId: client.chain.id,
        nonce,
        gasPrice: 360000n,
        gas: 169477n,
        to: "0x3aB946eEC2553114040dE82D2e18798a51cf1e14",
        value: parseEther('0.1'),
        data: encrypted,
        type: "seismic",
        encryptionPubkey: encryptionPubkey,
        encryptionNonce: encryptionNonce,
        messageVersion: 2,
    })
    console.log(typedData)
    console.log(signature)

    // // @ts-ignore
    // const hash = await client.sendRawTransaction({serializedTransaction: { data: typedData, signature }})
    // console.log(hash)
    // const receipt = await client.waitForTransactionReceipt({ hash })
    // console.log(receipt)
});

describe("DECRYPT", async () => {
    // const client = await createShieldedWalletClient({
    //     chain,
    //     account,
    //     transport: http(url),
    // });
    // const aesKey = client.getEncryption()
    // console.log(`AES Key: ${aesKey}`)
    // const plaintext = stringToHex("Hello, world!")
    // console.log(`Plaintext: ${plaintext}`)
    // const aesCipher = new AesGcmCrypto(aesKey)
    // const encryptionNonce = "0x7da3a99bf0f90d56551d99ea"
    // const encrypted = await aesCipher.encrypt(plaintext, encryptionNonce)

    // expect(encrypted).toBe("0x62a9351e3ad631c807e89586341d4a9ea3e64188aa2b65cd000140ea15")
})

describe("Seismic Contract", async () => {
    test(
        "deploy & call contracts with seismic tx",
        async () => {
            await testSeismicTx({ chain, url, account });
        },
        {
            timeout: TIMEOUT_MS,
        }
    );
});

describe("Seismic Transaction Encoding", async () => {
    test(
        "node detects and parses seismic transaction",
        async () => {
            await testSeismicTxEncoding({
                chain,
                account,
                url,
                encryptionSk,
                encryptionPubkey,
            });
        },
        {
            timeout: TIMEOUT_MS,
        }
    );
});

describe("Typed Data", async () => {
    test(
        "client can sign a seismic typed message",
        async () => {
            await testSeismicCallTypedData({
                chain,
                account,
                url,
                encryptionSk,
                encryptionPubkey,
            });
        },
        { timeout: TIMEOUT_MS }
    );

    test(
        "client can sign via eth_signTypedData",
        async () => {
            await testSeismicTxTypedData({
                account,
                chain,
                url,
                encryptionSk,
                encryptionPubkey,
            });
        },
        { timeout: TIMEOUT_MS }
    );
});

describe("AES", async () => {
    test("generates AES key correctly", testAesKeygen);
});

describe("Websocket Connection", () => {
    test(
        "should connect to the ws",
        async () => {
            await testWsConnection({
                chain,
                wsUrl,
            });
        },
        { timeout: TIMEOUT_MS }
    );
});

describe("Seismic Precompiles", async () => {
    test("RNG(1)", async () => await testRng({ chain, url }, 1), {
        timeout: TIMEOUT_MS,
    });
    test("RNG(8)", async () => await testRng({ chain, url }, 8), {
        timeout: TIMEOUT_MS,
    });
    test("RNG(16)", async () => await testRng({ chain, url }, 16), {
        timeout: TIMEOUT_MS,
    });
    test("RNG(32)", async () => await testRng({ chain, url }, 32), {
        timeout: TIMEOUT_MS,
    });
    test(
        "RNG(32, pers)",
        async () => await testRngWithPers({ chain, url }, 32),
        {
            timeout: TIMEOUT_MS,
        }
    );
    test("ECDH", async () => await testEcdh({ chain, url }), {
        timeout: TIMEOUT_MS,
    });
    test("HKDF(string)", async () => await testHkdfString({ chain, url }), {
        timeout: TIMEOUT_MS,
    });
    test("HKDF(hex)", async () => await testHkdfHex({ chain, url }), {
        timeout: TIMEOUT_MS,
    });
    test("AES-GCM", async () => await testAesGcm({ chain, url }), {
        timeout: TIMEOUT_MS,
    });
    test("secp256k1", async () => await testSecp256k1({ chain, url }), {
        timeout: TIMEOUT_MS,
    });
});

describe("Transaction Trace", async () => {
    test(
        "Seismic Tx removes input from trace",
        async () => {
            // TODO: do this in foundry too
            await testSeismicTxTrace({ chain, url, account });
        },
        {
            timeout: TIMEOUT_MS,
        }
    );
    test(
        "Legacy Tx keeps input in trace",
        async () => {
            await testLegacyTxTrace({ chain, url, account });
        },
        { timeout: TIMEOUT_MS }
    );
});

afterAll(async () => {
    await exitProcess();
});
