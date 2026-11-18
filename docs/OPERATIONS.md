# Operations and troubleshooting

## Prerequisites and lifecycle

Use Windows 11, PowerShell, Python 3.11/3.12 and [uv](https://docs.astral.sh/uv/getting-started/installation/). The normal dashboard uses Docker Desktop in Linux-container mode; native workers must run on Windows even though inference runs in Linux. Setup does not need historical datasets or GPU training.

```powershell
./setup.ps1 -Profile Demo
./start.ps1
# In another PowerShell window when finished:
./stop.ps1
```

Setup selects Python 3.11 by default; use `./setup.ps1 -Profile Demo -PythonVersion 3.12` for 3.12. It creates `.venv` with locked uv dependencies. `./helpers/doctor.ps1` checks prerequisites; `-SkipDocker` skips Docker checking.

Start uses the bundled native forest and opens the authenticated browser session. Keep the foreground launcher alive for its supervisor. Ctrl+C stops owned workers/service. Start refuses takeover of a busy port; do not kill an unrelated process to make the demo work. The helpers check Docker readiness; an installed Desktop may be started and awaited, but no engine change or silent Docker installation is intended.

The default address is `http://127.0.0.1:8767/`. A bare URL has no control credential; use the launcher's authenticated session. The token arrives in a URL fragment, is removed from the address bar, and is kept in tab-scoped sessionStorage. A new token fragment replaces it. Do not share session URLs, local credential files or screenshots containing credentials.

## Controls and evidence

Select **Run side-by-side demo**, or start benign append/invalidating rewrite separately. Each worker gets six generated fixtures in a dedicated owned temporary root. Stop controls target only the supervisor's own subprocesses. Files are independently hashed and validated between completed worker operations; model scores use separate per-actor measurements.

An invalid file does not imply an alert, and an alerted actor does not prove all its files are damaged. Benign saves may briefly invalidate a fixture. The current worker continues after detection. The UI separates live counts, saved test results, earlier alerts, peak score and file integrity. **All recorded workers** includes older jobs in the current service session.

## Configuration and lower-level entry points

The helper implementation is authoritative for available switches; use PowerShell `Get-Help ./start.ps1 -Detailed` and `Get-Help ./setup.ps1 -Detailed`. The root start wrapper supports `-NoBrowser` and `-NativeServer`. Ignored `.local/session.json` records the owned session for the stop helper. The legacy launcher remains at [launch.ps1](../demo/windows_streaming/launch.ps1). `-NoBrowser` prints the session URL; `-NativeServer` runs inference through local Python when Docker is unavailable.

The underlying service supports `--host`, `--port` and `--model`. Default model is [native-model.json](../demo/windows_streaming/native-model.json). The historical model can be explicitly loaded with `--model demo/windows_streaming/model.json` in an isolated manually managed service. This is not a deployment instruction to overwrite the current model. Agent transport currently targets localhost port 8767; changing only the service port does not configure an alternate agent.

Separate random environment credentials `WINDOWS_STREAM_TOKEN` (UI control) and `WINDOWS_AGENT_TOKEN` (agent) are required by the service. Helpers manage their session lifecycle. Do not hardcode them in code, command examples, reports or shell history. [.env.example](../.env.example) documents configuration placeholders, not usable credentials.

## Troubleshooting

| Symptom | Check/action |
|---|---|
| Docker unavailable | Start installed Docker Desktop; wait for Linux daemon readiness. Setup does not install Docker. |
| Port 8767 busy | Use the existing owned session or stop it with its lifecycle helper; identify unrelated ownership before taking action. |
| UI unauthorized | Reopen the launcher's session URL; a different browser/tab may not share sessionStorage. |
| Agent offline | Keep the native supervisor running; loss becomes visible after five seconds. Check its error output. |
| Native score unavailable | Inspect model validation/telemetry availability. Historical events lack required enriched fields. Unavailable is not a benign verdict. |
| Job capacity reached | Job history is bounded at 128; stop/restart the owned lab for a fresh session. |
| Cleanup error | Unexpected entries, links or ownership mismatch intentionally block cleanup. Inspect the reported owned path; do not recursively delete an unverified directory. |
| Training dependency missing | Run setup with Native for native fitting or Research for historical Torch/parser tasks. Demo only supplies runtime needs. |

Requests with invalid Origin/Host, malformed events, sequence gaps, missing identity, arbitrary paths or unknown commands are rejected. UI and agent credentials have separate permissions. Health exposes availability only. Runtime state is in memory; restarting loses session history. [Detailed runbook](../demo/windows_streaming/README.md).
