#!/usr/bin/env node
/**
 * Headless Chrome driver for the zkID bench harness.
 *
 * Spawns a local Chrome with CDP enabled, navigates /bench.html in both
 * `worker` and `main` modes, waits for the harness to set document.title to
 * "BENCH_DONE" (or "BENCH_FAILED"), scrapes the JSON report, and prints a
 * per-mode + side-by-side comparison table.
 *
 * Assumes the Vite dev server is already running (default: http://127.0.0.1:5174).
 *
 * Usage:
 *   node scripts/run-bench.mjs [--runs 3] [--url http://127.0.0.1:5174]
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
// Node 20 has no global WebSocket; fall back to the `ws` package.
const WS =
  typeof WebSocket !== "undefined" ? WebSocket : require("ws").WebSocket;

const args = process.argv.slice(2);
function flag(name, fallback) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return args[i + 1];
}

const RUNS = parseInt(flag("runs", "3"), 10);
const BASE_URL = flag("url", "http://127.0.0.1:5174");
const CHROME_BIN =
  flag("chrome", null) ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const DEBUG_PORT = parseInt(flag("port", "9333"), 10);

function log(msg) {
  process.stderr.write(`[bench] ${msg}\n`);
}

async function httpGetJson(path, method = "GET") {
  const resp = await fetch(`http://127.0.0.1:${DEBUG_PORT}${path}`, { method });
  if (!resp.ok) throw new Error(`${path} -> ${resp.status}`);
  return resp.json();
}

async function waitForCdp(attempts = 50) {
  for (let i = 0; i < attempts; i++) {
    try {
      await httpGetJson("/json/version");
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error("CDP never became ready");
}

/**
 * Minimal CDP client over WebSocket. Tracks pending requests by id.
 */
class CDP {
  constructor(url) {
    this.ws = new WS(url);
    this.nextId = 1;
    this.pending = new Map();
    this.events = new Map();
    this.ready = new Promise((resolve, reject) => {
      this.ws.addEventListener("open", () => resolve());
      this.ws.addEventListener("error", (e) =>
        reject(new Error(`CDP ws error: ${e.message || e}`)),
      );
    });
    this.ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
      } else if (msg.method) {
        const handlers = this.events.get(msg.method);
        if (handlers) for (const h of handlers) h(msg.params);
      }
    });
  }
  async send(method, params = {}) {
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(method, handler) {
    if (!this.events.has(method)) this.events.set(method, new Set());
    this.events.get(method).add(handler);
  }
  close() {
    this.ws.close();
  }
}

async function runOneMode(mode) {
  const url = `${BASE_URL}/bench.html?mode=${mode}&runs=${RUNS}`;
  log(`running ${mode} mode at ${url}`);

  // Open a fresh blank target so we can wire up CDP event handlers BEFORE
  // the bench page starts executing — otherwise early exceptions (e.g. a
  // WASM fetch failure during init) are lost before Runtime.enable runs.
  const target = await httpGetJson(`/json/new?about:blank`, "PUT");
  const cdp = new CDP(target.webSocketDebuggerUrl);
  await cdp.ready;

  try {
    // Forward page console messages + exceptions to our stderr so we see
    // crashes. Register handlers first, then enable domains, then navigate.
    cdp.on("Runtime.consoleAPICalled", (params) => {
      const text = (params.args || [])
        .map((a) => a.value ?? a.description ?? "?")
        .join(" ");
      log(`[page.${params.type}] ${text}`);
    });
    cdp.on("Runtime.exceptionThrown", (params) => {
      log(`[page.exception] ${params.exceptionDetails?.text ?? "?"}`);
    });
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");

    // Now navigate to the bench URL. Bench output is polled below via title.
    await cdp.send("Page.navigate", { url });

    // Poll document.title until the bench harness signals completion.
    const deadline = Date.now() + 10 * 60 * 1000; // 10 min per mode cap
    let finalTitle = "";
    while (Date.now() < deadline) {
      const { result } = await cdp.send("Runtime.evaluate", {
        expression: "document.title",
        returnByValue: true,
      });
      finalTitle = result.value ?? "";
      if (finalTitle === "BENCH_DONE" || finalTitle === "BENCH_FAILED") break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    if (finalTitle !== "BENCH_DONE") {
      // Scrape status + error anyway for diagnostics.
      const { result: errResult } = await cdp.send("Runtime.evaluate", {
        expression:
          "(document.getElementById('status')?.textContent || '') + '\\n---\\n' + " +
          "(document.getElementById('results')?.textContent || '')",
        returnByValue: true,
      });
      throw new Error(
        `bench did not complete (title=${finalTitle}):\n${errResult.value}`,
      );
    }

    // Read the JSON report from the data attribute on #results.
    const { result: reportResult } = await cdp.send("Runtime.evaluate", {
      expression:
        "document.getElementById('results')?.getAttribute('data-bench-report') || ''",
      returnByValue: true,
    });
    const reportJson = reportResult.value;
    if (!reportJson) throw new Error("no bench report found on page");
    return JSON.parse(reportJson);
  } finally {
    cdp.close();
    // Close the target so each mode is fully isolated.
    try {
      await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/close/${target.id}`, {
        method: "PUT",
      });
    } catch {
      // best-effort
    }
  }
}

function fmt(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${ms.toFixed(0)}ms`;
}

function printTable(reports) {
  const rows = [
    "step",
    "generate",
    "precompute",
    "present",
    "verify",
    "total pipeline",
    "init (once)",
  ];
  const modes = reports.map((r) => r.mode);
  const values = {
    generate: reports.map((r) => r.summary.medianGenerateMs),
    precompute: reports.map((r) => r.summary.medianPrecomputeMs),
    present: reports.map((r) => r.summary.medianPresentMs),
    verify: reports.map((r) => r.summary.medianVerifyMs),
    "total pipeline": reports.map((r) => r.summary.medianTotalPipelineMs),
    "init (once)": reports.map((r) => r.summary.medianInitMs),
  };
  const colWidth = 14;
  const pad = (s) => String(s).padEnd(colWidth);
  const padR = (s) => String(s).padStart(colWidth);

  console.log(
    `\n== zkID pipeline benchmark (median of ${reports[0].runs} runs) ==\n`,
  );
  console.log(
    pad("step") +
      modes.map((m) => padR(m)).join("") +
      padR("delta (worker - main)"),
  );
  console.log("-".repeat(colWidth * (modes.length + 2)));
  for (const key of Object.keys(values)) {
    const vs = values[key];
    const workerIdx = modes.indexOf("worker");
    const mainIdx = modes.indexOf("main");
    const delta =
      workerIdx >= 0 && mainIdx >= 0 ? vs[workerIdx] - vs[mainIdx] : null;
    console.log(
      pad(key) +
        vs.map((v) => padR(fmt(v))).join("") +
        padR(delta === null ? "-" : `${delta >= 0 ? "+" : ""}${fmt(delta)}`),
    );
  }
  console.log("");
  console.log(
    "Verified: " +
      reports.map((r) => `${r.mode}=${r.summary.allVerified}`).join(", "),
  );
  console.log(`User agent: ${reports[0].userAgent}`);
}

async function main() {
  const profileDir = mkdtempSync(join(tmpdir(), "zkid-chrome-bench-"));
  log(`launching Chrome (profile=${profileDir}, port=${DEBUG_PORT})`);
  const chrome = spawn(
    CHROME_BIN,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      `--remote-debugging-port=${DEBUG_PORT}`,
      `--user-data-dir=${profileDir}`,
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  chrome.stderr.on("data", () => {}); // drain

  try {
    await waitForCdp();
    const reports = [];
    for (const mode of ["main", "worker"]) {
      const report = await runOneMode(mode);
      reports.push(report);
      log(
        `${mode} mode: median total ${fmt(report.summary.medianTotalPipelineMs)}, ` +
          `verified=${report.summary.allVerified}`,
      );
    }
    printTable(reports);
    process.stdout.write(JSON.stringify(reports, null, 2) + "\n");
  } finally {
    chrome.kill("SIGTERM");
    try {
      rmSync(profileDir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
