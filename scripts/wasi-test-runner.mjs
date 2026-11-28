// Cargo runner for wasm32-wasip1 test binaries, using Node's built-in WASI (no wasmtime).
// CARGO_TARGET_WASM32_WASIP1_RUNNER="node scripts/wasi-test-runner.mjs"
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const [file, ...args] = process.argv.slice(2);
const wasi = new WASI({ version: "preview1", args: [file, ...args], env: process.env, returnOnExit: true });
const { instance } = await WebAssembly.instantiate(await readFile(file), wasi.getImportObject());
process.exit(wasi.start(instance));
