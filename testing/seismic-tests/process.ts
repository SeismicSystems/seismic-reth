import terminate from "terminate/promise";
import { spawn, ChildProcess } from "child_process";

type RunProcessOptions = {
  args?: readonly string[];
  waitMs?: number;
  cwd?: string;
};

export const runProcess = async (
  command: string,
  options: RunProcessOptions = {},
): Promise<ChildProcess> => {
  const { args = [], waitMs = 100, cwd } = options;
  const process = spawn(command, args, {
    cwd,
    stdio: "inherit",
  });
  await new Promise((resolve) => {
    process.on("spawn", () => setTimeout(resolve, waitMs));
  });
  return process;
};

export const killProcess = async (process: ChildProcess) => {
  const description = process.spawnargs.join(" ");
  if (!process.pid) {
    console.warn(`Cannot kill '${description}': has no pid`);
    return;
  }
  try {
    await terminate(process.pid);
    console.log(`Terminated process '${description}'`);
  } catch (error) {
    console.error(
      `Process[${process.pid}] failed to terminate '${description}': ${error}`,
    );
  }
};