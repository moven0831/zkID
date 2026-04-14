/**
 * Web Worker entry hosting Spartan2 proving WASM and Circom witness
 * calculators. Keeps the main thread responsive during the multi-second
 * proof generation pipeline.
 *
 * Spawned by WorkerBridge via:
 *   new Worker(new URL("./proving-worker.js", import.meta.url), { type: "module" })
 *
 * Protocol:
 *   in:  { id, type, payload }
 *   out: { id, ok: true, result } | { id, ok: false, error }
 *
 * Asset URLs (Spartan2 JS glue, Spartan2 WASM binary, witness_calculator
 * builder, JWT/Show circuit WASMs) are passed via the "init" message —
 * the worker is intentionally agnostic to where assets live so it can be
 * reused across deployments (web-demo, future SDK consumers, etc).
 */

// `self` in a dedicated worker is DedicatedWorkerGlobalScope (not Window).
// The SDK tsconfig includes DOM lib for the main-thread bridge; we cast here
// so addEventListener / postMessage have the worker-correct signatures.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ctx = self as any;

interface InitPayload {
  spartanWasmJsUrl: string;
  spartanWasmBinUrl: string;
  witnessCalculatorUrl: string;
  jwtCircomWasmUrl: string;
  showCircomWasmUrl: string;
}

interface SpartanModule {
  init?: () => void;
  initSync: (
    input: { module: WebAssembly.Module } | BufferSource | WebAssembly.Module,
  ) => unknown;
  precompute_from_witness: (
    pk: Uint8Array,
    wtns: Uint8Array,
  ) => { proof: Uint8Array; instance: Uint8Array; witness: Uint8Array };
  precompute_show_from_witness: (
    pk: Uint8Array,
    wtns: Uint8Array,
  ) => { proof: Uint8Array; instance: Uint8Array; witness: Uint8Array };
  present: (
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ) => {
    prepare_proof: Uint8Array;
    prepare_instance: Uint8Array;
    show_proof: Uint8Array;
    show_instance: Uint8Array;
  };
  verify: (
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ) => {
    valid: boolean;
    prepare_public_values: string[];
    show_public_values: string[];
    error: string | null;
  };
}

interface WitnessInstance {
  calculateWTNSBin: (
    input: Record<string, unknown>,
    sanityCheck?: boolean,
  ) => Promise<Uint8Array>;
  calculateWitness: (
    input: Record<string, unknown>,
    sanityCheck?: boolean,
  ) => Promise<bigint[]>;
}

type WitnessBuilder = (
  wasmBytes: ArrayBuffer | Uint8Array,
  options?: { sanityCheck?: boolean },
) => Promise<WitnessInstance>;

let spartan: SpartanModule | null = null;
let witnessBuilder: WitnessBuilder | null = null;
// Lazy-loader state: store the in-flight Promise (not the resolved value) so
// two messages arriving back-to-back (calculateJwtWitnessWtns +
// calculateJwtWitnessBigInts in the same precompute() call) both await the
// same fetch instead of racing each other into two parallel WASM downloads.
let jwtCalcPromise: Promise<WitnessInstance> | null = null;
let showCalcPromise: Promise<WitnessInstance> | null = null;
let initConfig: InitPayload | null = null;

function reviveBigInt(_key: string, value: unknown): unknown {
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  return value;
}

async function handleInit(payload: InitPayload): Promise<void> {
  initConfig = payload;

  // Spartan2 WASM: dynamic ESM import for JS glue, fetch + initSync for binary.
  // /* @vite-ignore */ tells Vite not to try to statically analyze the URL.
  const mod = (await import(/* @vite-ignore */ payload.spartanWasmJsUrl)) as SpartanModule;
  const wasmResp = await fetch(payload.spartanWasmBinUrl);
  if (!wasmResp.ok) {
    throw new Error(
      `Failed to fetch Spartan WASM binary at ${payload.spartanWasmBinUrl}: ` +
        `${wasmResp.status} ${wasmResp.statusText}`,
    );
  }
  const wasmBytes = await wasmResp.arrayBuffer();
  mod.initSync({ module: new WebAssembly.Module(wasmBytes) });
  if (mod.init) mod.init();
  spartan = mod;

  // Witness calculator builder — circuit WASMs are loaded lazily on first use.
  const wcMod = (await import(/* @vite-ignore */ payload.witnessCalculatorUrl)) as {
    default: WitnessBuilder;
  };
  witnessBuilder = wcMod.default;
}

async function loadCalc(url: string): Promise<WitnessInstance> {
  if (!witnessBuilder) throw new Error("Witness builder not initialized");
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Failed to fetch circuit WASM at ${url}: ${resp.status}`);
  }
  const wasmBytes = await resp.arrayBuffer();
  return witnessBuilder(wasmBytes, { sanityCheck: true });
}

function getJwtCalc(): Promise<WitnessInstance> {
  if (!jwtCalcPromise) {
    if (!initConfig) throw new Error("Worker not initialized");
    jwtCalcPromise = loadCalc(initConfig.jwtCircomWasmUrl);
  }
  return jwtCalcPromise;
}

function getShowCalc(): Promise<WitnessInstance> {
  if (!showCalcPromise) {
    if (!initConfig) throw new Error("Worker not initialized");
    showCalcPromise = loadCalc(initConfig.showCircomWasmUrl);
  }
  return showCalcPromise;
}

function getSpartan(): SpartanModule {
  if (!spartan) {
    throw new Error("Spartan WASM not initialized — send 'init' message first");
  }
  return spartan;
}

async function loadKeys(
  baseUrl: string,
  vcSize: string,
): Promise<{
  preparePk: Uint8Array;
  prepareVk: Uint8Array;
  showPk: Uint8Array;
  showVk: Uint8Array;
}> {
  const prefix = `${vcSize}_`;
  const filenames = [
    `${prefix}prepare_proving.key`,
    `${prefix}prepare_verifying.key`,
    `${prefix}show_proving.key`,
    `${prefix}show_verifying.key`,
  ];
  const fetched = await Promise.all(
    filenames.map(async (filename) => {
      const url = `${baseUrl}/${filename}`;
      const resp = await fetch(url);
      if (!resp.ok) {
        throw new Error(`Failed to load key ${url}: ${resp.status} ${resp.statusText}`);
      }
      return new Uint8Array(await resp.arrayBuffer());
    }),
  );
  const [preparePk, prepareVk, showPk, showVk] = fetched as [
    Uint8Array,
    Uint8Array,
    Uint8Array,
    Uint8Array,
  ];
  return { preparePk, prepareVk, showPk, showVk };
}

interface RequestMessage {
  id: number;
  type: string;
  payload: unknown;
}

interface ResponseMessage {
  id: number;
  ok: boolean;
  result?: unknown;
  error?: string;
}

ctx.addEventListener("message", async (ev: MessageEvent<RequestMessage>) => {
  const { id, type, payload } = ev.data;
  try {
    let result: unknown;
    switch (type) {
      case "init": {
        await handleInit(payload as InitPayload);
        result = null;
        break;
      }
      case "loadKeys": {
        const { baseUrl, vcSize } = payload as { baseUrl: string; vcSize: string };
        result = await loadKeys(baseUrl, vcSize);
        break;
      }
      case "calculateJwtWitnessWtns": {
        const { inputsJson } = payload as { inputsJson: string };
        const inputs = JSON.parse(inputsJson, reviveBigInt) as Record<string, unknown>;
        const calc = await getJwtCalc();
        const wtns = await calc.calculateWTNSBin(inputs, true);
        result = { wtns };
        break;
      }
      case "calculateShowWitnessWtns": {
        const { inputsJson } = payload as { inputsJson: string };
        const inputs = JSON.parse(inputsJson, reviveBigInt) as Record<string, unknown>;
        const calc = await getShowCalc();
        const wtns = await calc.calculateWTNSBin(inputs, true);
        result = { wtns };
        break;
      }
      case "calculateJwtWitnessBigInts": {
        const { inputsJson } = payload as { inputsJson: string };
        const inputs = JSON.parse(inputsJson, reviveBigInt) as Record<string, unknown>;
        const calc = await getJwtCalc();
        const witness = await calc.calculateWitness(inputs, true);
        result = { witness };
        break;
      }
      case "calculateShowWitnessBigInts": {
        const { inputsJson } = payload as { inputsJson: string };
        const inputs = JSON.parse(inputsJson, reviveBigInt) as Record<string, unknown>;
        const calc = await getShowCalc();
        const witness = await calc.calculateWitness(inputs, true);
        result = { witness };
        break;
      }
      case "precomputeFromWitness": {
        const { pk, wtns } = payload as { pk: Uint8Array; wtns: Uint8Array };
        const r = getSpartan().precompute_from_witness(pk, wtns);
        result = {
          proof: new Uint8Array(r.proof),
          instance: new Uint8Array(r.instance),
          witness: new Uint8Array(r.witness),
        };
        break;
      }
      case "precomputeShowFromWitness": {
        const { pk, wtns } = payload as { pk: Uint8Array; wtns: Uint8Array };
        const r = getSpartan().precompute_show_from_witness(pk, wtns);
        result = {
          proof: new Uint8Array(r.proof),
          instance: new Uint8Array(r.instance),
          witness: new Uint8Array(r.witness),
        };
        break;
      }
      case "present": {
        const p = payload as {
          preparePk: Uint8Array;
          prepareInstance: Uint8Array;
          prepareWitness: Uint8Array;
          showPk: Uint8Array;
          showInstance: Uint8Array;
          showWitness: Uint8Array;
        };
        const r = getSpartan().present(
          p.preparePk,
          p.prepareInstance,
          p.prepareWitness,
          p.showPk,
          p.showInstance,
          p.showWitness,
        );
        result = {
          prepareProof: new Uint8Array(r.prepare_proof),
          prepareInstance: new Uint8Array(r.prepare_instance),
          showProof: new Uint8Array(r.show_proof),
          showInstance: new Uint8Array(r.show_instance),
        };
        break;
      }
      case "verify": {
        const p = payload as {
          prepareProof: Uint8Array;
          prepareVk: Uint8Array;
          prepareInstance: Uint8Array;
          showProof: Uint8Array;
          showVk: Uint8Array;
          showInstance: Uint8Array;
        };
        const r = getSpartan().verify(
          p.prepareProof,
          p.prepareVk,
          p.prepareInstance,
          p.showProof,
          p.showVk,
          p.showInstance,
        );
        result = {
          valid: r.valid,
          preparePublicValues: r.prepare_public_values,
          showPublicValues: r.show_public_values,
          error: r.error ?? undefined,
        };
        break;
      }
      default:
        throw new Error(`Unknown message type: ${type}`);
    }
    const resp: ResponseMessage = { id, ok: true, result };
    ctx.postMessage(resp);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const resp: ResponseMessage = { id, ok: false, error: errMsg };
    ctx.postMessage(resp);
  }
});

// Mark this file as a module so TypeScript treats top-level vars as scoped.
export {};
