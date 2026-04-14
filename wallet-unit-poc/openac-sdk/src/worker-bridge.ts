/**
 * Main-thread proxy that runs the WASM proving pipeline (Spartan2 + Circom
 * witness calc) inside a dedicated Web Worker. Mirrors the WasmBridge surface
 * used by browser callers plus the `calculate*WitnessWtns()` methods that
 * absorb the BrowserWitnessCalculator, so pipeline code can be a drop-in
 * replacement.
 *
 * Asset URLs are injected via the config bag rather than hardcoded so the
 * worker is independent of any particular deployment layout.
 */

import { circuitInputsToJson } from "./utils.js";
import type {
  VcSize,
  SetupKeys,
  PrecomputeState,
  PresentationProof,
  VerificationResult,
} from "./wasm-bridge.js";

export interface WorkerBridgeConfig {
  /** URL to the Spartan2 WASM JS glue (ESM module, exports `initSync` + methods). */
  spartanWasmJsUrl: string;
  /** URL to the Spartan2 WASM binary (.wasm). */
  spartanWasmBinUrl: string;
  /** URL to the witness_calculator.js (ESM, default-exporting builder function). */
  witnessCalculatorUrl: string;
  /** URL to the JWT circuit Circom WASM binary. */
  jwtCircomWasmUrl: string;
  /** URL to the Show circuit Circom WASM binary. */
  showCircomWasmUrl: string;
  /** Optional Worker factory (for testing). Defaults to a module worker spawned from ./proving-worker.js. */
  workerFactory?: () => Worker;
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
}

interface ResponseMessage {
  id: number;
  ok: boolean;
  result?: unknown;
  error?: string;
}

export class WorkerBridge {
  private readonly config: WorkerBridgeConfig;
  private worker: Worker | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private initPromise: Promise<void> | null = null;

  constructor(config: WorkerBridgeConfig) {
    this.config = config;
  }

  get isInitialized(): boolean {
    return this.worker !== null && this.initPromise !== null;
  }

  /** Spawn the worker and load Spartan2 WASM + the witness builder. Idempotent. */
  async init(): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.doInit();
    return this.initPromise;
  }

  private async doInit(): Promise<void> {
    this.worker = this.spawn();
    this.worker.addEventListener("message", this.onMessage);
    this.worker.addEventListener("error", this.onError);
    try {
      await this.send("init", {
        spartanWasmJsUrl: this.config.spartanWasmJsUrl,
        spartanWasmBinUrl: this.config.spartanWasmBinUrl,
        witnessCalculatorUrl: this.config.witnessCalculatorUrl,
        jwtCircomWasmUrl: this.config.jwtCircomWasmUrl,
        showCircomWasmUrl: this.config.showCircomWasmUrl,
      });
    } catch (err) {
      this.terminate();
      throw err;
    }
  }

  private spawn(): Worker {
    if (this.config.workerFactory) return this.config.workerFactory();
    // Vite resolves this URL against the worker-bridge source file at build
    // time. The .ts extension is required for Vite to locate + bundle the
    // worker entry; at runtime the browser never sees .ts files.
    return new Worker(new URL("./proving-worker.ts", import.meta.url), {
      type: "module",
    });
  }

  /** Tear down the worker; rejects any outstanding requests. */
  terminate(): void {
    if (this.worker) {
      this.worker.removeEventListener("message", this.onMessage);
      this.worker.removeEventListener("error", this.onError);
      this.worker.terminate();
      this.worker = null;
    }
    for (const { reject } of this.pending.values()) {
      reject(new Error("WorkerBridge terminated"));
    }
    this.pending.clear();
    this.initPromise = null;
  }

  // --- Public methods (mirror WasmBridge + add witness calc) --------------

  async loadKeys(baseUrl: string, vcSize: VcSize): Promise<SetupKeys> {
    return this.send<SetupKeys>("loadKeys", { baseUrl, vcSize });
  }

  async calculateJwtWitnessWtns(
    inputs: Record<string, unknown>,
  ): Promise<Uint8Array> {
    const inputsJson = circuitInputsToJson(inputs);
    const { wtns } = await this.send<{ wtns: Uint8Array }>(
      "calculateJwtWitnessWtns",
      { inputsJson },
    );
    return wtns;
  }

  async calculateShowWitnessWtns(
    inputs: Record<string, unknown>,
  ): Promise<Uint8Array> {
    const inputsJson = circuitInputsToJson(inputs);
    const { wtns } = await this.send<{ wtns: Uint8Array }>(
      "calculateShowWitnessWtns",
      { inputsJson },
    );
    return wtns;
  }

  async calculateJwtWitnessBigInts(
    inputs: Record<string, unknown>,
  ): Promise<bigint[]> {
    const inputsJson = circuitInputsToJson(inputs);
    const { witness } = await this.send<{ witness: bigint[] }>(
      "calculateJwtWitnessBigInts",
      { inputsJson },
    );
    return witness;
  }

  async calculateShowWitnessBigInts(
    inputs: Record<string, unknown>,
  ): Promise<bigint[]> {
    const inputsJson = circuitInputsToJson(inputs);
    const { witness } = await this.send<{ witness: bigint[] }>(
      "calculateShowWitnessBigInts",
      { inputsJson },
    );
    return witness;
  }

  async precomputeFromWitness(
    pk: Uint8Array,
    wtns: Uint8Array,
  ): Promise<PrecomputeState> {
    return this.send<PrecomputeState>("precomputeFromWitness", { pk, wtns });
  }

  async precomputeShowFromWitness(
    pk: Uint8Array,
    wtns: Uint8Array,
  ): Promise<PrecomputeState> {
    return this.send<PrecomputeState>("precomputeShowFromWitness", {
      pk,
      wtns,
    });
  }

  async present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): Promise<PresentationProof> {
    return this.send<PresentationProof>("present", {
      preparePk,
      prepareInstance,
      prepareWitness,
      showPk,
      showInstance,
      showWitness,
    });
  }

  async verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    return this.send<VerificationResult>("verify", {
      prepareProof,
      prepareVk,
      prepareInstance,
      showProof,
      showVk,
      showInstance,
    });
  }

  // --- Internal -----------------------------------------------------------

  private send<T>(type: string, payload: unknown): Promise<T> {
    if (!this.worker) {
      return Promise.reject(
        new Error("WorkerBridge not initialized — call init() first"),
      );
    }
    const id = this.nextId++;
    const worker = this.worker;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      worker.postMessage({ id, type, payload });
    });
  }

  private onMessage = (ev: MessageEvent<ResponseMessage>): void => {
    const { id, ok, result, error } = ev.data;
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    if (ok) {
      pending.resolve(result);
    } else {
      pending.reject(new Error(error ?? "Worker error"));
    }
  };

  private onError = (ev: ErrorEvent): void => {
    const err = new Error(ev.message || "Worker error");
    for (const { reject } of this.pending.values()) reject(err);
    this.pending.clear();
    // Tear down the worker handle so a subsequent init() call can spawn a
    // fresh worker instead of posting to a crashed one forever.
    if (this.worker) {
      this.worker.removeEventListener("message", this.onMessage);
      this.worker.removeEventListener("error", this.onError);
      this.worker.terminate();
      this.worker = null;
    }
    this.initPromise = null;
  };
}
