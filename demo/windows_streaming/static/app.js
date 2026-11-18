'use strict';
const $ = id => document.getElementById(id);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let fragment = '';
try { fragment = decodeURIComponent(location.hash.slice(1)); } catch (_) { fragment = location.hash.slice(1); }
const launcherToken = /^[a-f0-9]{64}$/i.test(fragment) ? fragment : '';
if (launcherToken) sessionStorage.setItem('windowsStreamControl', launcherToken);
const token = launcherToken || sessionStorage.getItem('windowsStreamControl') || '';
if (launcherToken) history.replaceState(null, '', location.pathname + location.search);
let currentJobs = [];
try { currentJobs = JSON.parse(sessionStorage.getItem('windowsStreamCurrentJobs') || '[]'); if (!Array.isArray(currentJobs)) currentJobs = []; } catch (_) { currentJobs = []; }
let pending = false, refreshing = false, transportFailed = false, state = null;
let controlGeneration = 0;
let startNoticeActive = false;
const active = job => ['queued', 'running', 'stopping'].includes(job.status);
const number = value => typeof value === 'number' && Number.isFinite(value);
const score = value => number(value) ? (value * 100).toFixed(1) : '—';
const time = value => number(value) ? new Date(value * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}) : 'Time unavailable';
const kindName = kind => kind === 'benign' ? 'Genuine append' : kind === 'destructive' ? 'Destructive rewrite' : 'Observed process';
const saveJobs = () => sessionStorage.setItem('windowsStreamCurrentJobs', JSON.stringify(currentJobs));
function setText(id, value) { if ($(id).textContent !== String(value)) $(id).textContent = value; }
function setNotice(message, error = false) { setText('notice', message); $('notice').className = error ? 'error' : ''; }
function controls() {
  const disabled = pending || transportFailed || !state?.agent_online || !state?.model_available;
  for (const id of ['compare', 'benign', 'destructive']) $(id).disabled = disabled;
  document.querySelectorAll('[data-stop]').forEach(button => { button.disabled = pending || transportFailed || !state?.agent_online; });
  $('compare').textContent = pending ? 'Sending worker controls…' : 'Run side-by-side demo ↗';
}
async function api(path, data) {
  const response = await fetch(path, {method:data ? 'POST' : 'GET', headers:{Authorization:'Bearer ' + token, ...(data ? {'Content-Type':'application/json'} : {})}, body:data ? JSON.stringify(data) : undefined});
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || response.statusText);
  return value;
}
async function start(kinds) {
  if (pending || $('compare').disabled) return;
  pending = true; controlGeneration++; controls();
  startNoticeActive = false;
  const started = [];
  const alongside = kinds.length === 1 ? currentJobs.filter(id => state?.jobs?.some(job => job.job === id && active(job))) : [];
  setNotice('Starting the requested workers…');
  try {
    for (const kind of kinds) {
      const job = await api('/api/control', {action:'start', kind});
      started.push(job.job);
      currentJobs = [...alongside, ...started]; saveJobs(); $('scope').value = 'current';
    }
    startNoticeActive = true;
    setNotice(kinds.length === 2 ? 'Both workers queued. Waiting for actual native observations.' : 'Worker queued. Waiting for actual native observations.');
  } catch (error) {
    setNotice(started.length ? 'Only one worker started. The second start failed: ' + error.message : 'Worker start failed: ' + error.message, true);
  } finally { pending = false; await refresh(); controls(); }
}
async function stop(job) {
  if (pending || transportFailed || !state?.agent_online) return;
  pending = true; controlGeneration++; controls();
  startNoticeActive = false;
  try { await api('/api/control', {action:'stop', job}); setNotice('Stop requested for the owned worker. Waiting for confirmation.'); }
  catch (error) { setNotice('Stop failed: ' + error.message, true); }
  finally { pending = false; await refresh(); controls(); }
}
$('compare').addEventListener('click', () => start(['benign', 'destructive']));
$('benign').addEventListener('click', () => start(['benign']));
$('destructive').addEventListener('click', () => start(['destructive']));
$('actors').addEventListener('click', event => { const button = event.target.closest('[data-stop]'); if (button) stop(button.dataset.stop); });
$('scope').addEventListener('change', () => { if (state) render(state); });
// Replace a changing region as one batch, retaining expanded details and keyboard focus.
function updateRegion(element, html) {
  if (element._rendered === html) return;
  const expanded = new Set([...element.querySelectorAll('details[open]')].map(item => item.dataset.detail));
  const focused = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
  const scroll = element.scrollTop;
  element.innerHTML = html; element._rendered = html;
  element.querySelectorAll('details').forEach(item => { item.open = expanded.has(item.dataset.detail); });
  if (focused) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focused)?.focus({preventScroll:true});
  element.scrollTop = scroll;
}
function chart(actor, threshold) {
  const points = Array.isArray(actor?.history) ? actor.history.filter(point => number(point.seq)) : [];
  const available = points.filter(point => number(point.score));
  if (!available.length) return '<figure class="chart"><div class="chart-empty">No recorded score history available.</div><figcaption>Charts use server observations only. Missing scores are unavailable.</figcaption></figure>';
  const first = points[0].seq, last = points[points.length - 1].seq;
  const x = seq => 30 + (seq - first) / Math.max(1, last - first) * 390;
  const y = value => 126 - Math.max(0, Math.min(1, value)) * 110;
  let path = '', connected = false;
  for (const point of points) {
    if (!number(point.score)) { connected = false; continue; }
    path += (connected ? 'L' : 'M') + x(point.seq).toFixed(2) + ',' + y(point.score).toFixed(2) + ' ';
    connected = true;
  }
  const description = `${available.length} measured scores, events ${first} to ${last}. Latest recorded score ${score(available[available.length - 1].score)} out of 100. ${number(threshold) ? 'Alert threshold ' + score(threshold) + '.' : 'Threshold unavailable.'}`;
  const cutoff = number(threshold) ? `<line class="cutoff" x1="30" x2="420" y1="${y(threshold)}" y2="${y(threshold)}"/><text class="axis" x="417" y="${Math.max(10, y(threshold) - 5)}" text-anchor="end">Threshold ${score(threshold)}</text>` : '';
  return `<figure class="chart"><svg viewBox="0 0 440 154" role="img" aria-label="${escapeHtml(description)}"><line class="grid" x1="30" x2="420" y1="16" y2="16"/><line class="grid" x1="30" x2="420" y1="71" y2="71"/><line class="grid" x1="30" x2="420" y1="126" y2="126"/><text class="axis" x="1" y="20">100</text><text class="axis" x="7" y="75">50</text><text class="axis" x="13" y="130">0</text>${cutoff}<path class="trace" d="${path}"/>${available.map(point => `<circle class="point" cx="${x(point.seq)}" cy="${y(point.score)}" r="${available.length === 1 ? 3 : 1.1}"/>`).join('')}<text class="axis" x="30" y="147">Event ${first}</text><text class="axis" x="420" y="147" text-anchor="end">Event ${last}</text></svg><figcaption>${escapeHtml(description)} Score, not probability. Up to 512 recent points.</figcaption></figure>`;
}
function fileTiles(files) {
  return Array.from({length:6}, (_, index) => {
    const file = files.find(item => item.file === `fixture-${index}.jsonl`);
    const status = file?.valid === false ? 'Invalid' : file?.valid === true ? file.changed === true ? 'Changed · valid' : file.changed === false ? 'Intact' : 'Valid · change unknown' : 'Unknown';
    const style = file?.valid === false ? 'invalid' : file?.valid !== true ? 'unknown' : file.changed ? 'changed' : '';
    return `<div class="file ${style}"><strong>File ${index + 1}</strong><span>Generated fixture</span><span class="file-status">${status}</span><span>${file && number(file.bytes) ? file.bytes.toLocaleString() + ' bytes' : 'Awaiting evidence'}</span></div>`;
  }).join('');
}
function workerCard(job, actor, files, threshold) {
  const key = job.job;
  const flagged = Boolean(actor?.ever_alert || actor?.alert);
  const hasScore = number(actor?.score) && actor?.score_available !== false;
  const verdict = flagged ? 'Flagged by model' : hasScore ? 'Not flagged' : 'Score unavailable';
  const note = flagged ? 'This process crossed the model threshold. The flagged verdict is retained even if its latest score falls.' : hasScore ? 'No model alert observed for this process. This does not establish that its files are safe.' : 'No usable current model score. A missing score is not a safe verdict.';
  const firstAlert = actor?.first_alert_seq != null ? `Event ${actor.first_alert_seq}` : flagged ? 'Earlier alert' : 'None observed';
  const alertDetail = actor?.first_alert_seq != null ? `${time(actor.first_alert_time)}${number(actor.invalid_files_at_first_alert) ? ' · ' + actor.invalid_files_at_first_alert + ' invalid files observed at first alert' : ' · File evidence at first alert unavailable'}` : flagged ? 'First-alert details unavailable' : 'No first alert recorded';
  const telemetry = actor?.file_telemetry || {};
  const lifecycle = job.status || 'Unknown lifecycle';
  const safeKey = escapeHtml(key);
  return `<article class="worker ${flagged ? 'flagged' : ''}" aria-label="${escapeHtml(kindName(job.kind))} process"><div class="worker-head"><div><div class="scenario">SCENARIO · ${escapeHtml(lifecycle)}</div><h3>${escapeHtml(kindName(job.kind))}</h3></div><span class="badge ${flagged ? 'flagged' : hasScore ? 'clear' : ''}">${verdict}</span></div><div class="worker-body"><p class="verdict-note">${note}</p><div class="metrics"><div><span>Current score / 100</span><strong>${hasScore ? score(actor.score) : '—'}</strong></div><div><span>Peak score / 100</span><strong>${score(actor?.peak_score)}</strong></div><div><span>First model alert</span><strong class="first-alert">${escapeHtml(firstAlert)}</strong></div></div>${chart(actor, threshold)}<div class="file-heading"><h4>Independent file integrity</h4><span>${files.filter(file => file.valid === false).length} invalid / ${files.length} observed</span></div><div class="files">${fileTiles(files)}</div><details data-detail="${safeKey}"><summary data-focus="details-${safeKey}">Process & file evidence</summary><dl class="technical-list"><dt>Lifecycle</dt><dd>${escapeHtml(lifecycle)}</dd><dt>Process ID</dt><dd>${escapeHtml(actor?.pid ?? 'Awaiting process')}</dd><dt>Actor ID</dt><dd>${escapeHtml(actor?.actor || 'Not yet observed')}</dd><dt>Owned job</dt><dd>${escapeHtml(job.job)}</dd><dt>Events / window</dt><dd>${escapeHtml(actor?.seq ?? 0)} / ${escapeHtml(actor?.window ?? 0)}</dd><dt>First alert</dt><dd>${escapeHtml(alertDetail)}</dd><dt>Last operation</dt><dd>${escapeHtml(telemetry.op || 'Unknown')} · ${escapeHtml(telemetry.completed_bytes ?? 'Unknown')} bytes · offset ${escapeHtml(telemetry.byte_offset ?? 'Unknown')}</dd><dt>File size</dt><dd>${escapeHtml(telemetry.file_size_before ?? 'Unknown')} → ${escapeHtml(telemetry.file_size_after ?? 'Unknown')}</dd><dt>Missing score</dt><dd>${escapeHtml(actor?.score_unavailable_reason || (hasScore ? 'No missing current score' : 'Waiting for usable telemetry'))}</dd><dt>History evictions</dt><dd>${escapeHtml(actor?.history_evictions ?? 0)} from rolling feature window</dd></dl><ul class="hashes">${files.length ? files.map(file => `<li><b>${escapeHtml(file.file)}</b><br>Observed SHA256: ${escapeHtml(file.sha256 || 'Unknown')}<br>Baseline SHA256: ${escapeHtml(file.baseline_sha256 || 'Unknown')}</li>`).join('') : '<li>No file hashes observed.</li>'}</ul></details>${active(job) ? `<button class="stop" data-stop="${escapeHtml(job.job)}" data-focus="stop-${safeKey}">Stop this worker</button>` : ''}</div></article>`;
}
function milestoneRows(items, jobs) {
  if (!items.length) return '<li>No recorded milestones in this view.</li>';
  return items.slice().reverse().map(item => {
    const job = jobs.get(item.job), name = job ? kindName(job.kind) : 'Unmatched worker';
    const labels = {worker_started:'Worker started',worker_completed:'Worker completed',worker_stopped:'Worker stopped',worker_failed:'Worker failed',model_alert:'First model alert',file_invalid:'File became invalid',file_restored:'File validity restored'};
    let detail = item.message || labels[item.type] || 'Observed milestone';
    if (item.file && !detail.includes(item.file)) detail += ' · ' + item.file;
    if (number(item.score)) detail += ' · model score ' + score(item.score) + '/100';
    if (number(item.seq)) detail += ' · event ' + item.seq;
    return `<li class="${item.type === 'model_alert' || item.type === 'file_invalid' ? 'alert-event' : ''}"><time>${escapeHtml(time(item.time))}</time><div class="activity-copy"><b>${escapeHtml(detail)}</b><span class="event-type">${escapeHtml(name)} · ${escapeHtml(labels[item.type] || item.type || 'Observation')}</span></div></li>`;
  }).join('');
}
function render(snapshot) {
  const jobs = Array.isArray(snapshot.jobs) ? snapshot.jobs : [], actors = Array.isArray(snapshot.actors) ? snapshot.actors : [], files = Array.isArray(snapshot.files) ? snapshot.files : [];
  const retainedJobs = currentJobs.filter(id => jobs.some(job => job.job === id));
  if (retainedJobs.length !== currentJobs.length) { currentJobs = retainedJobs; saveJobs(); }
  if (startNoticeActive && currentJobs.length) {
    const current = jobs.filter(job => currentJobs.includes(job.job));
    if (current.some(job => job.status === 'failed')) {
      setNotice('A worker failed. Inspect the activity timeline and errors for details.', true);
      startNoticeActive = false;
    } else if (current.every(job => !active(job))) {
      setNotice('Demo finished. Final process scores and file observations remain below.');
      startNoticeActive = false;
    } else if (current.some(job => job.status === 'running' || job.status === 'stopping')) {
      setNotice('Workers are active. Showing live process scores and independent file checks.');
    }
  }
  const all = $('scope').value === 'all';
  const included = job => all || currentJobs.includes(job);
  const viewJobs = jobs.filter(job => included(job.job));
  const viewActors = actors.filter(actor => included(actor.job));
  const viewFiles = files.filter(file => included(file.job));
  setText('agent', snapshot.agent_online ? 'Native agent online' : 'Native agent offline'); $('agent').className = snapshot.agent_online ? 'online' : 'offline';
  setText('model', snapshot.model_available ? 'Streaming model loaded' : 'Model unavailable'); $('model').className = snapshot.model_available ? 'online' : 'offline';
  setText('threshold', number(snapshot.threshold) ? 'Alert threshold ' + score(snapshot.threshold) + ' / 100' : 'Alert threshold unavailable');
  setText('scope-note', all ? 'All retained workers in this server session. Counts below include older demos.' : currentJobs.length ? `Current demo: ${viewJobs.length} owned worker${viewJobs.length === 1 ? '' : 's'}. Earlier demos are available in “All recorded workers”.` : 'Current demo is empty. Start the side-by-side comparison to collect live observations.');
  setText('running-count', viewJobs.filter(active).length);
  setText('flagged-count', viewActors.filter(actor => actor.ever_alert || actor.alert).length);
  setText('invalid-count', viewFiles.filter(file => file.valid === false).length);
  setText('event-count', viewActors.reduce((total, actor) => total + (number(actor.seq) ? actor.seq : 0), 0).toLocaleString());
  let cards = '';
  for (const job of viewJobs) {
    const matching = viewActors.filter(actor => actor.job === job.job);
    for (const actor of matching.length ? matching : [null]) cards += workerCard(job, actor, viewFiles.filter(file => file.job === job.job), snapshot.threshold);
  }
  for (const actor of viewActors.filter(item => !jobs.some(job => job.job === item.job))) cards += workerCard({job:actor.job || actor.actor, kind:actor.kind, status:'Unknown lifecycle'}, actor, viewFiles.filter(file => file.actor === actor.actor), snapshot.threshold);
  updateRegion($('actors'), cards || '<div class="empty panel"><span class="empty-icon" aria-hidden="true">↗</span><h3>Your comparison starts here</h3><p>Run the side-by-side demo above. Actual process scores and file checks will appear as the native agent reports them.</p></div>');
  const activity = Array.isArray(snapshot.activity) ? snapshot.activity : [];
  const jobMap = new Map(jobs.map(job => [job.job, job]));
  updateRegion($('activity'), milestoneRows(activity.filter(item => included(item.job)).slice(-12), jobMap));
  updateRegion($('all-activity'), milestoneRows(activity, jobMap));
  const evaluation = snapshot.evaluation;
  if (evaluation && [evaluation.tp, evaluation.fn, evaluation.fp, evaluation.tn].every(number)) {
    setText('evaluation-detected', `${evaluation.tp}/${evaluation.tp + evaluation.fn}`);
    setText('evaluation-false', `${evaluation.fp}/${evaluation.fp + evaluation.tn}`);
    setText('performance', `Saved evaluation: ${evaluation.cohort || 'controlled native fixture tests'}. These are historical test captures, separate from the current demo.`);
  } else { setText('evaluation-detected', '—'); setText('evaluation-false', '—'); setText('performance', 'Saved evaluation unavailable. No historical results have been inferred.'); }
  const telemetry = snapshot.telemetry || {};
  setText('telemetry', `Model: ${snapshot.model_schema || 'unavailable'}. Retained actors: ${telemetry.actors ?? 'unknown'} / ${telemetry.actor_capacity ?? 'unknown'}. Rejected events: ${telemetry.rejected ?? 'unknown'}. Queued controls: ${telemetry.queued_commands ?? 'unknown'}. Chart histories are bounded to the eight most recent actors.`);
  setText('limits', Array.isArray(snapshot.limitations) ? snapshot.limitations.join(' ') : snapshot.limitations || 'Additional model limitations unavailable.');
  const errors = [...(snapshot.model_error ? [{message:'Model unavailable: ' + snapshot.model_error}] : []), ...(Array.isArray(snapshot.errors) ? snapshot.errors : [])];
  updateRegion($('errors'), errors.length ? errors.map(error => escapeHtml(error.message)).join('<br>') : 'None reported.');
  controls();
}
async function refresh() {
  if (refreshing || pending) return;
  refreshing = true;
  const generation = controlGeneration;
  try {
    const snapshot = await api('/api/state');
    if (generation !== controlGeneration) return;
    if (transportFailed) setNotice('Connection restored. Showing the latest server observations.');
    transportFailed = false; state = snapshot; render(snapshot);
  } catch (error) {
    if (generation !== controlGeneration) return;
    transportFailed = true;
    setNotice(token ? 'Connection unavailable: ' + error.message + '. Displayed observations may be stale.' : 'Open the launcher-provided URL containing your session token.', true);
    setText('agent', 'Connection unavailable'); $('agent').className = 'offline';
    setText('model', 'Model connection unavailable'); $('model').className = 'offline';
    controls();
  } finally { refreshing = false; }
}
refresh();
setInterval(refresh, 750);
