import { describe, test, expect, afterAll } from "bun:test"
import { createPublicClient, http, createWalletClient, defineChain} from "viem"
import { privateKeyToAccount } from "viem/accounts"
import { runSeismicReth } from "./seismicReth"
import { killProcess } from "./process"
const TEST_ADDRESS = '0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f'
const TEST_PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

const account = privateKeyToAccount(TEST_PRIVATE_KEY)

// TODO: move into seismic-viem
const seismicDevnet = defineChain({
  name: 'seismic',
  id: 12345,
  nativeCurrency: {
    name: 'Ether',
    symbol: 'ETH',
    decimals: 18
  },
  rpcUrls: {
    default: {
      http: ['http://localhost:8545'],
    },
  }
})

const seismicRethProcess = await runSeismicReth({ silent: true })

const exitProcess = async (code: 0 | 1) => {
  await killProcess(seismicRethProcess.process);
  process.exit(code)
}


const walletClient = createWalletClient({
  account,
  chain: seismicDevnet,
  transport: http()
})

describe('Seismic Transaction', () => {
  test('node detects and parses seismic transaction', async () => {
    const response = await walletClient.request({
      // @ts-ignore
      method: "seismic_sendTransaction",
      params: [
        {
          from: walletClient.account.address,
          to: TEST_ADDRESS,
          // @ts-ignore
          input: "0x123456",
          transaction_type: 74,
          gas: "0x33450",
          // @ts-ignore
          secretData: [
            {
              index: 4,
              preimage: BigInt(10),
              preimage_type: 'uint256',
              salt: "0x" + BigInt(0).toString(16).padStart(64, '0')
            }
          ]
        }
      ]
    });

    expect(response).toBeDefined();
    console.log('Seismic transaction response:', response);
  });
});

afterAll(async () => {
  await exitProcess(0)
})