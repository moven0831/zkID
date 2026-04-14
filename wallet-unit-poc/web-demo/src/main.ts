import {
  initWasm,
  generateTestCase,
  precompute,
  present,
  verify,
  formatMs,
  formatBytes,
  getDevicePublicKeyDisplay,
  getIssuerPublicKeyDisplay,
  getProvingMode,
  type StepLog,
} from "./pipeline.js";

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function setStepState(
  stepNum: number,
  state: "disabled" | "active" | "done" | "error"
) {
  const el = $(`step-${stepNum}`);
  el.classList.remove("disabled", "active", "done", "error");
  if (state !== "active") el.classList.add(state);
  if (state === "active") el.classList.add("active");
}

function enableButton(id: string) {
  const btn = $(id) as HTMLButtonElement;
  btn.disabled = false;
  btn.classList.remove("running");
}

function disableButton(id: string) {
  const btn = $(id) as HTMLButtonElement;
  btn.disabled = true;
  btn.classList.remove("running");
}

function setButtonRunning(id: string) {
  const btn = $(id) as HTMLButtonElement;
  btn.disabled = true;
  btn.classList.add("running");
}

function renderLogs(containerId: string, logs: StepLog[]) {
  const container = $(containerId);
  container.innerHTML = logs
    .map(
      (log) => `
    <div class="log-line">
      <span class="log-label">
        <span class="log-check">&#10003;</span>
        ${log.label}
      </span>
      <span class="log-duration">${formatMs(log.durationMs)}</span>
    </div>
  `
    )
    .join("");
}

function renderProgress(containerId: string, message: string) {
  const container = $(containerId);
  const existing = container.querySelector(".log-line.in-progress");
  if (existing) existing.remove();
  container.innerHTML += `
    <div class="log-line in-progress">
      <span class="log-label">
        <span class="log-spinner spinner">&#9696;</span>
        ${message}
      </span>
      <span class="log-duration">...</span>
    </div>
  `;
}

function setStatus(
  stepNum: number,
  state: "running" | "done" | "error",
  text: string,
  timing?: string
) {
  const container = $(`status-${stepNum}`);
  container.innerHTML = `
    <div class="status-bar ${state}">
      <span>${text}</span>
      ${timing ? `<span class="timing">${timing}</span>` : ""}
    </div>
  `;
}

function addDetail(containerId: string, label: string, value: string) {
  const container = $(containerId);
  container.innerHTML += `
    <div class="detail-item">
      <span class="detail-label">${label}:</span>
      <span class="detail-value">${value}</span>
    </div>
  `;
}

function showResultBanner(
  success: boolean,
  ageAbove18: boolean,
  deviceKey: { x: string; y: string } | null,
  verifyMs: number,
  error?: string
) {
  const banner = $("result-banner");
  banner.classList.remove("hidden", "success", "failure");
  banner.classList.add(success ? "success" : "failure");

  $("result-icon").innerHTML = success
    ? '<span style="color: var(--success)">&#10003;</span>'
    : '<span style="color: var(--error)">&#10007;</span>';

  $("result-title").textContent = success ? "VERIFIED" : "VERIFICATION FAILED";

  let detailsHtml = "";

  if (success) {
    detailsHtml += `
      <div class="result-row">
        <span class="result-label">Age Above 18:</span>
        <span class="result-value ${ageAbove18 ? "positive" : "negative"}">${ageAbove18 ? "Yes" : "No"}</span>
      </div>
    `;

    if (deviceKey) {
      detailsHtml += `
        <div class="result-row">
          <span class="result-label">Device Key X:</span>
          <span class="result-value">0x${truncateHex(deviceKey.x)}</span>
        </div>
        <div class="result-row">
          <span class="result-label">Device Key Y:</span>
          <span class="result-value">0x${truncateHex(deviceKey.y)}</span>
        </div>
      `;
    }

    detailsHtml += `
      <div class="result-row">
        <span class="result-label">Verified in:</span>
        <span class="result-value">${formatMs(verifyMs)}</span>
      </div>
    `;
  } else {
    detailsHtml += `
      <div class="result-row">
        <span class="result-label">Error:</span>
        <span class="result-value">${error ?? "Unknown error"}</span>
      </div>
    `;
  }

  $("result-details").innerHTML = detailsHtml;
}

function renderModeBadge(mode: "worker" | "main"): void {
  const existing = document.getElementById("mode-badge");
  if (existing) existing.remove();
  const badge = document.createElement("div");
  badge.id = "mode-badge";
  badge.textContent =
    mode === "worker" ? "mode: web worker" : "mode: main thread";
  badge.title =
    mode === "worker"
      ? "Proving runs in a dedicated Web Worker so the UI stays responsive. Add ?mode=main to the URL to use the main-thread path."
      : "Proving runs on the main thread (UI will freeze during proving). Remove ?mode=main from the URL to use the worker.";
  badge.style.cssText = [
    "position: fixed",
    "top: 8px",
    "right: 8px",
    "padding: 4px 10px",
    "font-size: 11px",
    "font-family: ui-monospace, monospace",
    "background: " + (mode === "worker" ? "#e6f9ed" : "#fff4d6"),
    "color: " + (mode === "worker" ? "#0a6b33" : "#7a5500"),
    "border: 1px solid " + (mode === "worker" ? "#34c77b" : "#e6b800"),
    "border-radius: 4px",
    "z-index: 9999",
  ].join(";");
  document.body.appendChild(badge);
}

function truncateHex(hex: string): string {
  const cleaned = hex.replace(/^0x/, "").replace(/[^0-9a-fA-F]/g, "");
  if (cleaned.length <= 20) return cleaned;
  return cleaned.slice(0, 16) + "...";
}

async function init() {
  const overlay = document.createElement("div");
  overlay.className = "init-overlay";
  overlay.id = "init-overlay";
  overlay.innerHTML = `
    <div class="init-box">
      <h2>Initializing zkID Demo</h2>
      <div class="init-status" id="init-status">Loading WASM module...</div>
      <div class="init-logs" id="init-logs"></div>
    </div>
  `;
  document.body.appendChild(overlay);

  try {
    const logs = await initWasm((msg) => {
      $("init-status").textContent = msg;
    });

    const logsEl = $("init-logs");
    logsEl.innerHTML = logs
      .map((l) => `<div>&#10003; ${l.label} — ${formatMs(l.durationMs)}</div>`)
      .join("");

    const mode = getProvingMode();
    const modeLabel = mode === "worker"
      ? "Web Worker (off-main-thread)"
      : "Main thread (?mode=main)";
    $("init-status").textContent = `Ready! Proving mode: ${modeLabel}`;
    renderModeBadge(mode);

    await new Promise((r) => setTimeout(r, 600));
    overlay.classList.add("hidden");
    setTimeout(() => overlay.remove(), 300);

    setStepState(1, "active");
    enableButton("btn-generate");
  } catch (err) {
    $("init-status").textContent = `Error: ${err}`;
    console.error("Init failed:", err);
  }
}

async function handleGenerate() {
  setButtonRunning("btn-generate");
  setStatus(1, "running", "Generating...");

  try {
    const result = generateTestCase();

    renderLogs("details-1", result.logs);

    const issuerKey = getIssuerPublicKeyDisplay();
    const deviceKey = getDevicePublicKeyDisplay();
    addDetail("details-1", "JWT", `${result.jwt.length} chars`);
    addDetail("details-1", "Disclosures", `${result.disclosures.length} claims`);
    addDetail(
      "details-1",
      "Claims",
      result.claims.map((c) => `${c.key}=${c.value}`).join(", ")
    );
    addDetail("details-1", "Issuer Key X", `0x${issuerKey.x}`);
    addDetail("details-1", "Device Key X", `0x${deviceKey.x}`);

    setStatus(1, "done", "Test case generated", formatMs(result.totalMs));
    setStepState(1, "done");
    disableButton("btn-generate");

    setStepState(2, "active");
    enableButton("btn-precompute");
  } catch (err) {
    setStatus(1, "error", `Error: ${err}`);
    setStepState(1, "error");
    enableButton("btn-generate");
    console.error("Generate failed:", err);
  }
}

async function handlePrecompute() {
  setButtonRunning("btn-precompute");
  setStatus(2, "running", "Precomputing...");
  $("details-2").innerHTML = "";

  try {
    const result = await precompute((msg) => {
      renderProgress("details-2", msg);
    });

    renderLogs("details-2", result.logs);
    addDetail(
      "details-2",
      "Prepare proof",
      formatBytes(result.prepareProof.length)
    );
    addDetail(
      "details-2",
      "Prepare instance",
      formatBytes(result.prepareInstance.length)
    );
    addDetail(
      "details-2",
      "JWT witness outputs",
      `w[97] (KeyBindingX), w[98] (KeyBindingY)`
    );

    setStatus(2, "done", "Precompute complete", formatMs(result.totalMs));
    setStepState(2, "done");
    disableButton("btn-precompute");

    setStepState(3, "active");
    enableButton("btn-present");
  } catch (err) {
    setStatus(2, "error", `Error: ${err}`);
    setStepState(2, "error");
    enableButton("btn-precompute");
    console.error("Precompute failed:", err);
  }
}

async function handlePresent() {
  setButtonRunning("btn-present");
  setStatus(3, "running", "Presenting...");
  $("details-3").innerHTML = "";

  try {
    const result = await present((msg) => {
      renderProgress("details-3", msg);
    });

    renderLogs("details-3", result.logs);
    addDetail(
      "details-3",
      "Show proof",
      formatBytes(result.showProof.length)
    );
    addDetail(
      "details-3",
      "Prepare proof (reblinded)",
      formatBytes(result.prepareProof.length)
    );
    addDetail(
      "details-3",
      "Age above 18 (witness)",
      result.ageAbove18 ? "Yes" : "No"
    );

    setStatus(3, "done", "Presentation complete", formatMs(result.totalMs));
    setStepState(3, "done");
    disableButton("btn-present");

    setStepState(4, "active");
    enableButton("btn-verify");
  } catch (err) {
    setStatus(3, "error", `Error: ${err}`);
    setStepState(3, "error");
    enableButton("btn-present");
    console.error("Present failed:", err);
  }
}

async function handleVerify() {
  setButtonRunning("btn-verify");
  setStatus(4, "running", "Verifying...");
  $("details-4").innerHTML = "";

  try {
    const result = await verify((msg) => {
      renderProgress("details-4", msg);
    });

    renderLogs("details-4", result.logs);

    if (result.valid) {
      setStatus(4, "done", "Verification passed", formatMs(result.totalMs));
      setStepState(4, "done");
    } else {
      setStatus(
        4,
        "error",
        `Verification failed: ${result.error}`,
        formatMs(result.totalMs)
      );
      setStepState(4, "error");
    }

    disableButton("btn-verify");

    showResultBanner(
      result.valid,
      result.ageAbove18,
      result.deviceKey,
      result.totalMs,
      result.error
    );
  } catch (err) {
    setStatus(4, "error", `Error: ${err}`);
    setStepState(4, "error");
    enableButton("btn-verify");
    console.error("Verify failed:", err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("btn-generate").addEventListener("click", handleGenerate);
  $("btn-precompute").addEventListener("click", handlePrecompute);
  $("btn-present").addEventListener("click", handlePresent);
  $("btn-verify").addEventListener("click", handleVerify);
  init();
});
