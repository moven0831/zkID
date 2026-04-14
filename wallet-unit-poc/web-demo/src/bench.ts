/**
 * Headless benchmark runner for the zkID pipeline.
 *
 * Runs the full pipeline (generate → precompute → present → verify) N times
 * and dumps a structured JSON report to #results. The proving mode is picked
 * up from the URL query string by pipeline.ts (`?mode=worker|main`). Runs
 * default to 3; override with `?runs=5`.
 *
 * Automation hook: when every run completes, `document.title` becomes
 * "BENCH_DONE". If any run throws, the title becomes "BENCH_FAILED" — the
 * driver (headless Chrome CDP) polls the title to know when to scrape.
 */

import {
  initWasm,
  generateTestCase,
  precompute,
  present,
  verify,
  getProvingMode,
  type StepLog,
} from "./pipeline.js";

interface RunTimings {
  run: number;
  initMs: number | null;
  generateMs: number;
  precomputeMs: number;
  presentMs: number;
  verifyMs: number;
  totalPipelineMs: number;
  verified: boolean;
  stepLogs: {
    init: StepLog[];
    generate: StepLog[];
    precompute: StepLog[];
    present: StepLog[];
    verify: StepLog[];
  };
}

interface BenchReport {
  mode: "worker" | "main";
  runs: number;
  timings: RunTimings[];
  summary: {
    medianInitMs: number;
    medianGenerateMs: number;
    medianPrecomputeMs: number;
    medianPresentMs: number;
    medianVerifyMs: number;
    medianTotalPipelineMs: number;
    allVerified: boolean;
  };
  userAgent: string;
  timestamp: string;
}

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const sorted = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2
    : (sorted[mid] ?? 0);
}

function setStatus(msg: string): void {
  const el = document.getElementById("status");
  if (el) el.textContent = msg;
}

function writeResults(report: BenchReport): void {
  const el = document.getElementById("results");
  if (!el) return;
  // Pretty-print so manual inspection is readable and still JSON-parseable.
  el.textContent = JSON.stringify(report, null, 2);
  // Also publish as text/plain for anyone scraping.
  el.setAttribute("data-bench-report", JSON.stringify(report));
}

async function runOnce(run: number): Promise<RunTimings> {
  const initLogs: StepLog[] = []; // init already ran before this

  setStatus(`Run ${run}: generate...`);
  const t0 = performance.now();
  const gen = generateTestCase();
  const genMs = performance.now() - t0;

  setStatus(`Run ${run}: precompute...`);
  const t1 = performance.now();
  const pre = await precompute();
  const preMs = performance.now() - t1;

  setStatus(`Run ${run}: present...`);
  const t2 = performance.now();
  const prs = await present();
  const prsMs = performance.now() - t2;

  setStatus(`Run ${run}: verify...`);
  const t3 = performance.now();
  const vfy = await verify();
  const vfyMs = performance.now() - t3;

  return {
    run,
    initMs: null,
    generateMs: genMs,
    precomputeMs: preMs,
    presentMs: prsMs,
    verifyMs: vfyMs,
    totalPipelineMs: genMs + preMs + prsMs + vfyMs,
    verified: vfy.valid,
    stepLogs: {
      init: initLogs,
      generate: gen.logs,
      precompute: pre.logs,
      present: prs.logs,
      verify: vfy.logs,
    },
  };
}

async function main(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  const runs = Math.max(1, parseInt(params.get("runs") ?? "3", 10) || 3);

  setStatus("Initializing WASM + keys...");
  const initT0 = performance.now();
  const initLogs = await initWasm((msg) => setStatus(msg));
  const initMs = performance.now() - initT0;

  const mode = getProvingMode();
  setStatus(`Init complete (${mode} mode, ${initMs.toFixed(0)}ms). Running ${runs} iterations...`);

  const timings: RunTimings[] = [];
  for (let i = 1; i <= runs; i++) {
    const t = await runOnce(i);
    if (i === 1) t.initMs = initMs;
    // Attach the init step logs only once (to the first run).
    if (i === 1) t.stepLogs.init = initLogs;
    timings.push(t);
  }

  const report: BenchReport = {
    mode,
    runs,
    timings,
    summary: {
      medianInitMs: initMs,
      medianGenerateMs: median(timings.map((t) => t.generateMs)),
      medianPrecomputeMs: median(timings.map((t) => t.precomputeMs)),
      medianPresentMs: median(timings.map((t) => t.presentMs)),
      medianVerifyMs: median(timings.map((t) => t.verifyMs)),
      medianTotalPipelineMs: median(timings.map((t) => t.totalPipelineMs)),
      allVerified: timings.every((t) => t.verified),
    },
    userAgent: navigator.userAgent,
    timestamp: new Date().toISOString(),
  };

  writeResults(report);
  setStatus(
    `Done: ${mode} mode, ${runs} runs, median total ${report.summary.medianTotalPipelineMs.toFixed(0)}ms, ` +
      `verified=${report.summary.allVerified}.`,
  );
  document.title = "BENCH_DONE";
}

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  console.error("bench failed:", err);
  setStatus(`FAILED: ${msg}`);
  const el = document.getElementById("results");
  if (el) el.textContent = `FAILED:\n${msg}`;
  document.title = "BENCH_FAILED";
});
