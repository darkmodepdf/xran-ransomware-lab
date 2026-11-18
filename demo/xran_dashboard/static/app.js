"use strict";

const $ = (id) => document.getElementById(id);
const metricColumns = ["accuracy", "precision", "recall", "f1", "specificity", "fpr", "mcc", "roc_auc", "average_precision"];
const percentMetrics = new Set(["accuracy", "precision", "recall", "f1", "specificity", "fpr", "fnr", "balanced_accuracy"]);
const integer = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
let report = null;
let metadata = null;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function metric(value, key) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "Unavailable";
  return percentMetrics.has(key) ? `${(value * 100).toFixed(2)}%` : value.toFixed(4);
}

function metricCell(metrics, key, reasons = {}) {
  const value = metrics?.[key];
  const cell = node("td", metric(value, key));
  if (value === null || value === undefined) {
    cell.className = "unavailable";
    cell.title = reasons[key] || metrics?.undefined_reasons?.[key] || "Undefined for this cohort or not exported.";
  }
  return cell;
}

function friendly(key) {
  return key.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

// Exported content always becomes text, never markup or executable URLs.
function evidence(value, depth = 0) {
  const container = node("div", undefined, "evidence");
  if (value === null || value === undefined || (typeof value === "object" && Object.keys(value).length === 0)) {
    container.append(node("p", "No evidence exported for this section."));
    return container;
  }
  if (Array.isArray(value)) {
    const list = node("ul");
    value.forEach((entry, index) => {
      const item = node("li");
      if (entry && typeof entry === "object") {
        const details = node("details");
        details.append(node("summary", entry.name || entry.source || entry.label || `Entry ${index + 1}`), evidence(entry, depth + 1));
        item.append(details);
      } else item.textContent = entry === null ? "Unavailable" : String(entry);
      list.append(item);
    });
    container.append(list);
  } else if (typeof value === "object") {
    const list = node("dl");
    Object.entries(value).forEach(([key, entry]) => {
      if (entry !== null && typeof entry === "object") {
        const details = node("details");
        details.append(node("summary", friendly(key)), depth < 8 ? evidence(entry, depth + 1) : node("p", JSON.stringify(entry)));
        container.append(details);
      } else {
        const pair = node("div");
        pair.append(node("dt", friendly(key)), node("dd", entry == null ? "Unavailable" : String(entry)));
        list.append(pair);
      }
    });
    container.prepend(list);
  } else container.append(node("p", String(value)));
  return container;
}

function setEvidence(id, value) {
  $(id).replaceChildren(evidence(value));
}

function updateLimitations() {
  const values = [...new Set([...(metadata?.limitations || []), ...(report?.limitations || [])])];
  if (values.length) $("limitations").replaceChildren(...values.map((value) => node("li", value)));
}

function setStatus(state, title, detail) {
  $("status").dataset.state = state;
  $("state").textContent = title;
  $("state-detail").textContent = detail;
}

function showUnavailable(error) {
  report = null;
  $("results").hidden = true;
  $("empty-state").hidden = false;
  const missing = error.code === "evaluation_unavailable";
  $("empty-title").textContent = missing ? "No measured results available" : "Evaluation could not be displayed";
  $("empty-message").textContent = error.message || "The dashboard could not read the evaluation export.";
  $("provenance").textContent = "No evaluation metrics are being displayed.";
  setStatus(missing ? "pending" : "error", missing ? "Awaiting evaluation export" : "Export unavailable", "No model scores or metrics have been substituted.");
  updateLimitations();
}

function showModel(identifier) {
  const model = report.models.find((entry) => entry.id === identifier);
  if (!model) return;
  $("selected-title").textContent = `${model.label} · seed ${model.seed}`;
  for (const row of $("comparison-body").children) row.classList.toggle("selected-row", row.dataset.modelId === identifier);
  ["tp", "fn", "tn", "fp"].forEach((key) => { $(key).textContent = integer.format(model.confusion[key]); });
  const support = Object.values(model.confusion).reduce((total, count) => total + count, 0);
  $("selected-support").textContent = `${integer.format(support)} feature groups`;
  $("fnr").textContent = metric(model.metrics.fnr, "fnr");
  $("balanced-accuracy").textContent = metric(model.metrics.balanced_accuracy, "balanced_accuracy");
  const calibration = model.calibration;
  const enabled = model.alarm_enabled ?? calibration.alarm_enabled;
  const threshold = model.threshold ?? calibration.threshold;
  $("threshold").textContent = enabled ? String(threshold) : "Alarms disabled";
  $("calibration-rate").textContent = calibration.alerts !== undefined && calibration.n !== undefined
    ? `${integer.format(calibration.alerts)} / ${integer.format(calibration.n)} · ${metric(calibration.actual_fpr, "fpr")}`
    : metric(calibration.actual_fpr, "fpr");
  $("observed-fpr").textContent = metric(model.metrics.fpr, "fpr");
  setEvidence("class-evidence", { class_report: model.class_report ?? model.metrics.class_report,
    intervals: model.intervals ?? model.metrics.intervals, undefined_reasons: model.undefined_reasons ?? model.metrics.undefined_reasons });
  setEvidence("calibration-evidence", { calibration, provenance: model.provenance,
    bundle_sha256: model.bundle_sha256, runtime_sha256: model.runtime_sha256 });
  const sourceBody = $("source-body");
  sourceBody.replaceChildren();
  for (const source of model.source_metrics || []) {
    const row = node("tr");
    const header = node("th", source.source);
    header.scope = "row";
    row.append(header, node("td", integer.format(source.groups ?? Object.values(source.confusion).reduce((a, b) => a + b, 0))));
    ["tp", "fn", "tn", "fp"].forEach((key) => row.append(node("td", integer.format(source.confusion[key]))));
    ["recall", "fpr", "f1"].forEach((key) => row.append(metricCell(source.metrics, key, source.undefined_reasons)));
    sourceBody.append(row);
  }
  if (!sourceBody.children.length) {
    const row = node("tr"), cell = node("td", "No source-specific evaluation was exported.", "unavailable");
    cell.colSpan = 9;
    row.append(cell);
    sourceBody.append(row);
  }
}

function showReport(value) {
  const previousModel = $("model-select").value;
  report = value;
  $("empty-state").hidden = true;
  $("results").hidden = false;
  const dataset = report.dataset;
  [["raw-rows", dataset.raw_rows], ["cohort-groups", dataset.cohort_groups], ["test-groups", dataset.test_groups ?? Object.values(report.models[0].confusion).reduce((a, b) => a + b, 0)]]
    .forEach(([id, count]) => { $(id).textContent = Number.isInteger(count) ? integer.format(count) : "Unavailable"; });
  $("nominal-budget").textContent = metric(report.nominal_fpr_budget, "fpr");
  $("cohort-note").textContent = dataset.name || "XRan released feature dataset";
  const body = $("comparison-body");
  body.replaceChildren();
  $("model-select").replaceChildren();
  for (const model of report.models) {
    const row = node("tr"), header = node("th", model.label);
    row.dataset.modelId = model.id;
    header.scope = "row";
    header.append(node("small", `Seed ${model.seed}`));
    row.append(header);
    metricColumns.forEach((key) => row.append(metricCell(model.metrics, key, model.undefined_reasons)));
    body.append(row);
    const option = node("option", `${model.label} · seed ${model.seed}`);
    option.value = model.id;
    $("model-select").append(option);
  }
  $("model-select").value = report.models.some((model) => model.id === previousModel) ? previousModel : report.models[0].id;
  showModel($("model-select").value);
  setEvidence("dataset-evidence", dataset);
  setEvidence("diagnostic-evidence", report.diagnostics);
  updateLimitations();
  setStatus("ready", "Measured evaluation loaded", `${report.models.length} evaluated models · endpoint classification`);
  $("provenance").textContent = `${report.schema} · Generated ${report.generated_at || "date not exported"} · ${metadata?.report_file || "evaluation export"}`;
}

async function load() {
  $("refresh").disabled = true;
  setStatus("loading", "Reading evaluation", "Checking the exported evidence.");
  try {
    const [metadataResponse, evaluationResponse] = await Promise.all([
      fetch("/api/xran/metadata", { cache: "no-store" }), fetch("/api/xran/evaluation", { cache: "no-store" }),
    ]);
    if (metadataResponse.ok) {
      metadata = await metadataResponse.json();
      $("runtime").textContent = metadata.runtime;
    }
    const value = await evaluationResponse.json();
    if (!evaluationResponse.ok) showUnavailable(value);
    else showReport(value);
  } catch (error) {
    showUnavailable({ code: "connection_error", message: `Could not load the evaluation: ${error.message}` });
  } finally {
    $("refresh").disabled = false;
  }
}

$("model-select").addEventListener("change", (event) => showModel(event.target.value));
$("refresh").addEventListener("click", load);
load();
