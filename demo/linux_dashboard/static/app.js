"use strict";

const byId = (id) => document.getElementById(id);
const controls = byId("controls");
const scenario = byId("scenario");
const speed = byId("speed");
const start = byId("start");
const stop = byId("stop");
const download = byId("download");
const canvas = byId("plot");
const eventsBody = byId("events");
const scoreText = (score) => score === null ? "Disabled" : score.toFixed(4);

let metadata;
let controller;
let observations = [];
let result;
let total = 0;
let alert = null;
let blocked = 0;
let framePending = false;
let currentScenario;
let currentRate;

function setStatus(kind, title, detail) {
  byId("status").dataset.state = kind;
  byId("state").textContent = title;
  byId("state-detail").textContent = detail;
}

function setControls(running) {
  for (const element of [scenario, speed, start]) element.disabled = running || !metadata;
  stop.hidden = !running;
}

function setFixture() {
  const fixture = metadata.fixtures[scenario.value];
  byId("provenance").textContent = [
    metadata.source, "Trace " + fixture.trace_id, fixture.role, fixture.family, fixture.selection,
  ].filter(Boolean).join(" · ");
  resetRun(fixture.count);
  setStatus("ready", "Ready", fixture.count + " captured events in the selected trace.");
}

function resetRun(count) {
  total = count;
  observations = [];
  result = null;
  alert = null;
  blocked = 0;
  download.disabled = true;
  byId("throughput").textContent = "";
  byId("integrity").textContent = "SHA-256 verification runs when the replay finishes.";
  byId("file-map").replaceChildren();
  requestRender();
}

function renderRows() {
  if (!observations.length) {
    const row = eventsBody.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 5;
    cell.className = "table-empty";
    cell.textContent = "Start a replay to see observations.";
    eventsBody.replaceChildren(row);
    return;
  }
  const rows = observations.slice(-14).reverse().map((event) => {
    const row = document.createElement("tr");
    if (event.alert) row.className = "first-alert";
    const cells = [
      event.operation.toUpperCase(), "#" + event.index, scoreText(event.score), "Written",
      event.blocked ? "Blocked" : event.alert ? "Written · alert" : "Written",
    ];
    for (const value of cells) row.insertCell().textContent = value;
    if (event.blocked) row.lastElementChild.className = "blocked-cell";
    return row;
  });
  eventsBody.replaceChildren(...rows);
}

function drawChart() {
  const { width, height } = canvas.getBoundingClientRect();
  if (width < 100 || height < 65) return;
  const scale = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);

  const left = 29;
  const right = width - 11;
  const top = 9;
  const bottom = height - 25;
  const x = (index) => left + (index - 1) * (right - left) / Math.max(1, total - 1);
  const y = (score) => top + (1 - score) * (bottom - top);

  function line(x0, y0, x1, y1, color, dash = []) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    ctx.setLineDash(dash);
    ctx.beginPath();
    ctx.moveTo(x0, y0);
    ctx.lineTo(x1, y1);
    ctx.stroke();
  }

  ctx.fillStyle = "#51635a";
  ctx.font = "10px Consolas, monospace";
  ctx.textBaseline = "middle";
  for (const tick of [0, 0.25, 0.5, 0.75, 1]) {
    line(left, y(tick), right, y(tick), "#e1e9e2");
    ctx.fillText(String(tick), 0, y(tick));
  }
  if (total > 0) {
    const ticks = total < 5 ? [1, total] : [1, Math.round(total / 2), total];
    for (const tick of new Set(ticks)) {
      ctx.textAlign = tick === 1 ? "left" : tick === total ? "right" : "center";
      ctx.fillText(String(tick), x(tick), bottom + 13);
    }
    ctx.textAlign = "center";
    ctx.fillText("Captured event index", (left + right) / 2, height - 2);
  }

  const tau = metadata?.threshold;
  if (typeof tau === "number") line(left, y(tau), right, y(tau), "#789087", [5, 4]);
  if (!observations.length) return;
  if (alert) line(x(alert.index), top, x(alert.index), bottom, "#a94825", [4, 3]);

  ctx.strokeStyle = "#28745a";
  ctx.lineWidth = 2;
  ctx.setLineDash([]);
  ctx.beginPath();
  for (const event of observations) {
    if (event.index === 1) ctx.moveTo(x(event.index), y(event.score));
    else ctx.lineTo(x(event.index), y(event.score));
  }
  ctx.stroke();

  const endpoint = alert || observations.at(-1);
  ctx.fillStyle = alert ? "#a94825" : "#28745a";
  ctx.beginPath();
  ctx.arc(x(endpoint.index), y(endpoint.score), 3.5, 0, 2 * Math.PI);
  ctx.fill();
}

function requestRender() {
  if (framePending) return;
  framePending = true;
  requestAnimationFrame(() => {
    framePending = false;
    const count = observations.length;
    const last = observations.at(-1);
    byId("observed").textContent = total ? count + " / " + total : "—";
    byId("current-score").textContent = last ? scoreText(last.score) : "—";
    byId("first-alert").textContent = alert ? "#" + alert.index : result ? "None" : "—";
    byId("first-alert").dataset.active = String(Boolean(alert));
    byId("gate").textContent = alert ? "Gate closed" : "Gate open";
    byId("gate").dataset.state = alert ? "closed" : "open";
    byId("monitor-count").textContent = String(count);
    byId("protected-count").textContent = String(count - blocked);
    byId("blocked-count").textContent = String(blocked);
    for (const [id, value] of [["monitor-bar", count], ["protected-bar", count - blocked]]) {
      const meter = byId(id);
      meter.max = total || 1;
      meter.value = value;
    }
    renderRows();
    drawChart();
  });
}

function consume(event) {
  if (event.kind === "start") {
    setStatus("running", "Replaying", "Scoring captured events and applying paired marker writes.");
  } else if (event.kind === "step") {
    observations.push(event);
    if (event.blocked) blocked += 1;
    if (event.alert) {
      alert = event;
      setStatus("alert", "Alert at event " + event.index, "The write gate is closed for subsequent attempts.");
    }
    requestRender();
  } else if (event.kind === "finish") {
    result = event;
    const verifiedCount = event.files.filter((file) => file.protected_sha256 === file.initial_sha256).length;
    setStatus(event.first_alert === null ? "ready" : "alert", "Replay complete",
      event.first_alert === null ? "No alert was emitted." : "First alert at event " + event.first_alert + " · " + event.blocked + " writes blocked.");
    byId("integrity").textContent = verifiedCount + " of " + event.files.length + " gated files retain their starting SHA-256.";
    byId("throughput").textContent = event.achieved_eps.toFixed(1) + " events/s · " + (event.elapsed_ms / 1000).toFixed(2) + " s";
    byId("file-map").replaceChildren(...event.files.map((file) => {
      const cell = document.createElement("i");
      cell.dataset.modified = String(file.protected_sha256 !== file.initial_sha256);
      return cell;
    }));
    download.disabled = false;
    requestRender();
  } else if (event.kind === "error") {
    throw new Error(event.error);
  }
}

async function readStream(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let partial = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const lines = (partial + decoder.decode(value, { stream: true })).split("\n");
      partial = lines.pop();
      for (const line of lines) {
        if (line) consume(JSON.parse(line));
      }
    }
    partial += decoder.decode();
    if (partial.trim()) consume(JSON.parse(partial));
    if (!result) throw new Error("The replay ended before integrity verification.");
  } finally {
    await reader.cancel();
  }
}

controls.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!metadata || controller) return;
  currentScenario = scenario.value;
  currentRate = Number(speed.value);
  resetRun(metadata.fixtures[currentScenario].count);
  controller = new AbortController();
  setControls(true);
  setStatus("running", "Starting replay", "Generating disposable file fixtures.");
  try {
    const response = await fetch("/api/replay", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: currentScenario, rate: currentRate }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error((await response.json()).error || "Replay request failed.");
    await readStream(response);
  } catch (error) {
    if (controller.signal.aborted) setStatus("ready", "Replay stopped", "Start again to create a fresh pair of fixtures.");
    else setStatus("error", "Replay failed", error.message);
  } finally {
    controller = null;
    setControls(false);
  }
});

stop.addEventListener("click", () => controller?.abort());
scenario.addEventListener("change", setFixture);
download.addEventListener("click", () => {
  if (!result) return;
  const report = {
    model: { architecture: metadata.architecture, onnx_sha256: metadata.onnx_sha256, bundle_sha256: metadata.bundle_sha256 },
    runtime: { engine: metadata.runtime, os: metadata.os }, alpha: metadata.alpha, threshold: metadata.threshold,
    source: metadata.source, replay: { scenario: currentScenario, rate: currentRate, fixture: metadata.fixtures[currentScenario] },
    observations, result,
  };
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + "\n"], { type: "application/json" }));
  link.download = "raneval-" + currentScenario + "-replay.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});

new ResizeObserver(requestRender).observe(canvas.parentElement);
fetch("/api/metadata")
  .then((response) => {
    if (!response.ok) throw new Error("Unable to read the staged model and traces.");
    return response.json();
  })
  .then((value) => {
    metadata = value;
    for (const [id, fixture] of Object.entries(metadata.fixtures)) scenario.add(new Option(fixture.label, id));
    for (const rate of metadata.rates) speed.add(new Option(rate ? rate + " events / s" : "Unpaced", rate, false, rate === 20));
    byId("runtime").textContent = metadata.os + " · " + metadata.runtime;
    byId("model").textContent = metadata.architecture.toUpperCase() + " · nominal " + (metadata.alpha * 100) + "% calibration";
    byId("threshold").textContent = scoreText(metadata.threshold);
    byId("threshold-key").hidden = metadata.threshold === null;
    setControls(false);
    setFixture();
  })
  .catch((error) => setStatus("error", "Dashboard unavailable", error.message));
