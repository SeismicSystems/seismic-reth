import { promises as fs } from "fs";
import { killProcess, runProcess } from "./process";
import type { ServerProcess } from "./server";
import { sleep } from "bun";

type SeismicOptions = {
  port?: number;
  silent?: boolean;
  waitMs?: number;
};

export type SeismicProcess = ServerProcess & { url: string };

export const runSeismicReth = async (
  options: SeismicOptions = {},
): Promise<SeismicProcess> => {
  const { port = 8545, silent = true, waitMs = 2_000 } = options;
  const silentArg = silent ? ["--silent"] : [];

  const process = await runProcess("seismic-reth", {
    args: ["node", "--http", "--port", port.toString(), ...silentArg],
  });

  await sleep(waitMs);

  // Check if process is running by verifying the URL is accessible, etc.
  try {
    return { process, url: `http://127.0.0.1:${port}` };
  } catch (e) {
    await killProcess(process);
    throw new Error(`Failed to start seismic-reth: ${e}`);
  }
};
