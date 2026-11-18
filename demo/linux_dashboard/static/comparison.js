"use strict";

(() => {
  const view = (id) => document.getElementById(id);
  const tabs = Array.from(document.querySelectorAll(".dashboard-tabs [role=tab]"));
  const modelLabels = { counts: "Event count", cnn: "CNN", gru: "GRU", gru_refit: "GRU refit", gru_context: "GRU + context" };
  const countFormat = new Intl.NumberFormat();
  const decimalFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });
  const percentFormat = new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 2 });
  let benchmarkRequest = null;

  function recordCell(value, detail = "", rowHeading = false) {
    const cell = document.createElement(rowHeading ? "th" : "td");
    if (rowHeading) cell.scope = "row";
    cell.textContent = value;
    if (detail) {
      const note = document.createElement("small");
      note.textContent = detail;
      cell.append(note);
    }
    return cell;
  }

  function recordRow(...cells) {
    const row = document.createElement("tr");
    row.append(...cells);
    return row;
  }

  function ratio(numerator, denominator) {
    if (!Number.isInteger(numerator) || !Number.isInteger(denominator) || numerator < 0 || numerator > denominator) {
      throw new Error("Invalid counts in the benchmark result.");
    }
    return countFormat.format(numerator) + " / " + countFormat.format(denominator);
  }

  function alertEvent(result) {
    if (!result.alerts) return "No alert";
    if (result.median_first_event == null) return "—";
    if (!Number.isFinite(result.median_first_event) || result.median_first_event < 1) {
      throw new Error("Invalid first alert in the benchmark result.");
    }
    return "Event " + decimalFormat.format(result.median_first_event);
  }

  function elapsed(result) {
    if (!result.alerts || result.median_first_ms == null) return "";
    if (!Number.isFinite(result.median_first_ms) || result.median_first_ms < 0) {
      throw new Error("Invalid alert time in the benchmark result.");
    }
    return result.median_first_ms >= 1000
      ? decimalFormat.format(result.median_first_ms / 1000) + " s"
      : decimalFormat.format(result.median_first_ms) + " ms";
  }

  function renderModel(model, label, eventHorizon, hasFreshRansomware) {
    const positive = model.ransomware_test;
    const cells = [recordCell(label, "", true)];
    if (hasFreshRansomware) {
      cells.push(recordCell(alertEvent(positive), elapsed(positive)));
      if (eventHorizon !== null) cells.push(recordCell(ratio(positive.early_alerts, positive.total)));
      cells.push(recordCell(ratio(positive.alerts, positive.total)));
    }
    for (const result of [model.calibration, model.benign_test]) {
      const rate = result.total ? percentFormat.format(result.alerts / result.total) : "";
      cells.push(recordCell(ratio(result.alerts, result.total), rate));
    }
    return recordRow(...cells);
  }

  function renderGroups(name, groupHeading, groups, ids, labels, showDelay, earlyHorizon = null) {
    const columns = [groupHeading, ...ids.map((id) => labels[id])].map((label) => {
      const cell = document.createElement("th");
      cell.scope = "col";
      cell.textContent = label;
      return cell;
    });
    const rows = groups.map((group) => recordRow(recordCell(group.name, "", true), ...ids.map((id) => {
      const result = group.models[id];
      if (!result) return recordCell("—");
      const totalText = ratio(result.alerts, group.total);
      if (showDelay && earlyHorizon !== null) {
        const early = ratio(result.early_alerts, group.total) + " by event " + countFormat.format(earlyHorizon);
        return recordCell(alertEvent(result), early);
      }
      return showDelay ? recordCell(alertEvent(result), totalText + " detected") : recordCell(totalText);
    })));
    view("comparison-" + name + "-columns").replaceChildren(recordRow(...columns));
    view("comparison-" + name + "-rows").replaceChildren(...rows);
  }

  function listItem(text) {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }

  function sourceItem(source) {
    const item = listItem(source.name + " · " + source.detail);
    if (!source.url) return item;
    const url = new URL(source.url, window.location.href);
    if (url.protocol === "http:" || url.protocol === "https:") {
      const link = document.createElement("a");
      link.href = url.href;
      link.textContent = "Source";
      link.setAttribute("aria-label", "Source for " + source.name);
      item.append(" ", link);
    }
    return item;
  }

  function renderObservation(result) {
    view("comparison-observed").hidden = !result;
    if (!result) return;
    const observed = countFormat.format(result.observed_events);
    const scored = countFormat.format(result.scored_events);
    const first = result.first_alert ? "Alert at event "
      + countFormat.format(result.first_alert.stream_event ?? result.first_alert.event) : "No alert";
    view("comparison-observed-status").textContent = first;
    view("comparison-observed-status").dataset.state = result.first_alert ? "closed" : "open";
    view("comparison-observed-workload").textContent = result.workload;
    view("comparison-observed-detail").textContent = observed + " completed calls observed · " + scored
      + " scored with " + (result.model_label || "the frozen contextual model")
      + (result.beyond_calibration_horizon ? " · Calls beyond the calibration horizon "
        + countFormat.format(result.beyond_calibration_horizon) : "")
      + (result.operating_point_validated_for_observed_order === false
        ? " · Live ordering needs separate false-alarm validation" : "");
  }

  function renderProcessComparison(result) {
    view("process-comparison").hidden = !result;
    if (!result) return;
    if (result.schema !== "raneval-linux-process-v1" || !Array.isArray(result.models)) {
      throw new Error("Unsupported task comparison.");
    }
    const schedule = view("process-schedule");
    schedule.replaceChildren(...result.schedules.map(([warmup, background]) => {
      const option = document.createElement("option");
      option.value = "warmup" + warmup + "-background" + background;
      option.textContent = background === 1 ? "Equal activity" : "3× background activity";
      return option;
    }));
    schedule.value = result.primary_schedule;
    schedule.onchange = () => renderProcessRows(result, schedule.value);
    renderProcessRows(result, schedule.value);
    view("process-comparison-method").textContent = "Each model uses a 5% target for any alarm in a benign session. "
      + "Per-task history keeps each task’s calls together. Early detection means an alert within 120 ransomware operations.";
    view("process-comparison-limit").textContent = "The same five archived ransomware captures are replayed against different "
      + "benign backgrounds. Detection counts describe constructed sessions. A per-task detection requires an alert on an "
      + "injected task. Shared-history alerts describe the combined stream. The cutoff stays fixed as background load changes.";
  }

  function renderProcessRows(result, schedule) {
    const models = result.models.map((model) => ({ ...model, ...model.schedules[schedule] }));
    const rows = models.map((model) => recordRow(
      recordCell(model.label.replace(/ (per task|shared history)$/, ""), "", true),
      recordCell(model.scope === "actor" ? "Per task" : "Shared"),
      recordCell(ratio(model.calibration.alerts, model.calibration.total)),
      recordCell(ratio(model.benign_test.alerts, model.benign_test.total)),
      recordCell(ratio(model.positive_test.early_alerts, model.positive_test.sessions)),
      recordCell(ratio(model.positive_test.post_onset_alerts, model.positive_test.sessions)),
      recordCell(model.positive_test.benign_actor_alerts === null ? "—"
        : ratio(model.positive_test.benign_actor_alerts, model.positive_test.sessions)),
    ));
    view("process-comparison-rows").replaceChildren(...rows);
    const adapted = models.find((model) => model.id === "gru_task_actor");
    view("process-family-result").textContent = adapted ? "Task-trained GRU · "
      + adapted.families.map((family) => family.name + " " + ratio(family.detected, family.total)).join(" · ") : "";
  }

  function renderBenchmark(benchmark) {
    if (benchmark.schema !== "raneval-linux-benchmark-v1" || !Number.isFinite(benchmark.budget.target_rate)
        || benchmark.budget.target_rate < 0 || benchmark.budget.target_rate > 1
        || typeof benchmark.budget.unit !== "string" || !benchmark.budget.unit) {
      throw new Error("Unsupported benchmark result.");
    }
    renderProcessComparison(benchmark.process_benchmark);
    const models = new Map(benchmark.models.map((model) => [model.id, model]));
    const modelIds = Object.keys(modelLabels).filter((id) => models.has(id));
    if (!modelIds.length || benchmark.models.length !== modelIds.length) {
      throw new Error("Benchmark contains an unsupported or duplicate model.");
    }
    const labels = models.has("gru_refit") ? { ...modelLabels, gru: "GRU baseline" } : modelLabels;
    const eventHorizon = benchmark.early_event_horizon ?? null;
    if (eventHorizon !== null && (!Number.isInteger(eventHorizon) || eventHorizon < 1)) {
      throw new Error("Invalid early detection horizon in the benchmark result.");
    }
    const hasFreshRansomware = benchmark.families.length > 0;
    const modelRows = modelIds.map((id) => renderModel(models.get(id), labels[id], eventHorizon, hasFreshRansomware));
    const regression = benchmark.regression_families ?? [];
    const sourceRows = benchmark.provenance.map(sourceItem);
    const limitations = benchmark.limitations.map(listItem);

    view("benchmark-title").textContent = benchmark.title;
    view("benchmark-title").hidden = !benchmark.title;
    view("benchmark-rate").textContent = percentFormat.format(benchmark.budget.target_rate);
    view("benchmark-unit").textContent = "Per " + benchmark.budget.unit;
    view("comparison-budget").hidden = false;
    const earlyHeading = view("comparison-early-heading");
    earlyHeading.hidden = !hasFreshRansomware || eventHorizon === null;
    view("comparison-first-alert-heading").hidden = !hasFreshRansomware;
    view("comparison-detected-heading").hidden = !hasFreshRansomware;
    view("comparison-summary-heading").textContent = benchmark.process_benchmark ? "Earlier single-capture holdout"
      : hasFreshRansomware ? "Held-out results" : "Fresh benign holdout";
    view("comparison-benign-heading").textContent = benchmark.process_benchmark
      ? "Earlier false alarms by workload" : "False alarms by benign workload";
    view("comparison-regression-heading").textContent = benchmark.process_benchmark
      ? "Earlier single-capture ransomware checks" : "Previously evaluated ransomware captures";
    if (eventHorizon !== null) earlyHeading.textContent = "Detected by event " + countFormat.format(eventHorizon);
    view("comparison-summary-rows").replaceChildren(...modelRows);
    const previous = benchmark.historical_gru;
    const historyNote = view("comparison-history");
    const paired = benchmark.evaluation?.context?.paired_against_gru_refit?.log_rotation;
    if (paired) {
      const removed = countFormat.format(paired.removed_alerts);
      const added = countFormat.format(paired.added_alerts);
      historyNote.textContent = "GRU + context vs. GRU refit on paired log rotations · Alarms removed "
        + removed + " · Alarms added " + added;
    } else if (previous) {
      const rotation = ratio(previous.log_rotation.alerts, previous.log_rotation.total);
      const benign = ratio(previous.benign_test.alerts, previous.benign_test.total);
      historyNote.textContent = "The earlier GRU threshold flagged " + rotation + " log rotations and " + benign
        + " benign runs on this same fresh holdout.";
    }
    historyNote.hidden = !paired && !previous;
    renderGroups("family", "Family", benchmark.families, modelIds, labels, true);
    const familiesPanel = view("comparison-families-panel");
    familiesPanel.hidden = !benchmark.families.length;
    familiesPanel.parentElement.classList.toggle("single-cohort", !benchmark.families.length);
    renderGroups("benign", "Workload", benchmark.benign_workloads, modelIds, labels, false);
    const regressionIds = modelIds.filter((id) => regression.some((group) => group.models[id]));
    renderGroups("regression", "Family", regression, regressionIds, labels, true, eventHorizon);
    view("comparison-regression-panel").hidden = !regression.length;
    renderObservation(benchmark.observed_benign);
    view("benchmark-method").textContent = benchmark.method;
    const split = benchmark.evaluation?.capture_counts;
    if (split && [split.train, split.calibrate, split.test].every((count) => Number.isInteger(count) && count > 0)) {
      view("benchmark-split").textContent = (benchmark.process_benchmark ? "Earlier single-capture study · " : "")
        + ["Training " + countFormat.format(split.train),
        "Calibration " + countFormat.format(split.calibrate), "Test " + countFormat.format(split.test)].join(" · ") + " captures";
      view("benchmark-split").hidden = false;
    }
    view("benchmark-sources").replaceChildren(...sourceRows);
    view("benchmark-provenance").hidden = !sourceRows.length;
    view("benchmark-limitations").replaceChildren(...limitations);
    view("comparison-limitations").hidden = !limitations.length;
    view("comparison-results").hidden = false;
    view("comparison-status").hidden = true;
  }

  function loadBenchmark() {
    if (benchmarkRequest) return;
    const status = view("comparison-status");
    status.textContent = "Loading benchmark results.";
    benchmarkRequest = fetch("/api/benchmark")
      .then(async (response) => {
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Unable to load benchmark results.");
        renderBenchmark(result);
      })
      .catch((error) => {
        status.textContent = error.message;
        benchmarkRequest = null;
      });
  }

  function activate(tab, focus = false) {
    for (const item of tabs) {
      const active = item === tab;
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
      view(item.getAttribute("aria-controls")).hidden = !active;
    }
    const showComparison = tab.id === "comparison-tab";
    history.replaceState(null, "", location.pathname + location.search + (showComparison ? "#comparison" : ""));
    if (showComparison) loadBenchmark();
    if (focus) tab.focus();
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activate(tab));
    tab.addEventListener("keydown", (event) => {
      let next;
      if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      else return;
      event.preventDefault();
      activate(tabs[next], true);
    });
  });
  function tabFromLocation() {
    return view(location.hash === "#comparison" ? "comparison-tab" : "replay-tab");
  }

  window.addEventListener("hashchange", () => activate(tabFromLocation()));
  if (location.hash === "#comparison") activate(tabFromLocation());
})();
