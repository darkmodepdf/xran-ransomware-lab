# Live file-response demonstration

The runner creates two sets of generated dummy files with identical initial bytes. A fixed workload appends a harmless marker to one fixture per observation. Both modes receive the same scores. Monitor-only keeps accepting writes after an alert, and enforcement blocks subsequent writes. The report measures actual changes with SHA-256. The write that triggered the alert is counted as completed because the gate evaluates its score afterward.

The built-in score stream is synthetic and exercises the response gate. The optional score bundle demonstrates enforcement against previously recorded scores. For live inference, the model container runs the frozen classifier one API observation at a time. The model consumes a Windows API trace. Linux container file operations supply the dummy workload for the response gate.

From the project root with Docker in Linux-container mode:

```text
docker build --pull -t raneval-response-demo demo
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 128m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 raneval-response-demo
```

The image pins the Python base image by digest and runs as an unprivileged UID. Its demo writes go to a fresh temporary directory on the container's tmpfs. Use a dedicated Linux container and keep host volumes, Docker sockets, and credentials outside it. See [Docker run](https://docs.docker.com/engine/containers/run/), [tmpfs mounts](https://docs.docker.com/engine/storage/tmpfs/), and the [none network driver](https://docs.docker.com/engine/network/drivers/none/).

For a machine-readable report, append `--json --delay-ms 0` to the run command. The default fixture crosses the threshold at observation four and schedules ten writes. The report records identical starting file hashes, each mode's final hashes, the alert and gate timestamps relative to the run, and the number of blocked writes. A verified container run changed all ten fixtures in monitor-only mode and four in enforcement mode. [Synthetic run result](synthetic-result.json)

For an imported score bundle, attach stdin with `docker run -i`, retain the runtime flags above, and pass `--scores-stdin`. Supply JSON and close stdin. The `run_id` should identify the frozen output that supplied the scores. The threshold must match the exported run's threshold, and the bundle holds at most 120 scores.

```json
{"scores": [0.10, 0.35, 0.80, 0.90], "threshold": 0.70, "run_id": "example-recorded-run"}
```

Local CLI checks use the standard library:

```text
python -m unittest discover -s demo -p test_runner.py -v
```

## Live inference with a frozen model

Use a dedicated input directory containing the bundle, `frozen.json` with `bundle_sha256`, and a demo trace `apis.jsonl` with one JSON string per API observation, up to 120 observations. Use a trace from the same telemetry format as training. Keep the calibrated operating point from the model bundle. Freeze the demo trace separately from the research scoring cohorts.

Generate offline reference scores on the same bundle and API trace using the shared scoring command. With Python, CPU PyTorch and the project source importable, run the following and replace `HASH_FROM_FROZEN_JSON` with the bundle hash:

```text
python -m raneval.score --bundle demo-input/bundle.pt --apis demo-input/apis.jsonl --expected-sha256 HASH_FROM_FROZEN_JSON --output demo-input/scores.jsonl --device cpu --alpha 0.05
```

From the project root in PowerShell, build the CPU model image and run it with just that input directory mounted read-only:

```powershell
$demoInput = (Resolve-Path -LiteralPath 'demo-input').Path
$bundleHash = (Get-Content -LiteralPath (Join-Path $demoInput 'frozen.json') -Raw | ConvertFrom-Json).bundle_sha256
docker build -f demo/Dockerfile.model -t raneval-model-demo .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 --mount "type=bind,source=$demoInput,target=/inputs,readonly" raneval-model-demo --model-bundle /inputs/bundle.pt --bundle-sha256 $bundleHash --apis /inputs/apis.jsonl --alpha 0.05 --reference-scores /inputs/scores.jsonl
```

Pass `--json --delay-ms 0` for the scores, checksum, frozen threshold, first alert, observed write counts, file hashes, and parity result. The parity check compares the same checkpoint, input and operating point, with an absolute score tolerance of `1e-6` and exact first-alert equality. The image installs CPU PyTorch once in a cached build layer. [PyTorch wheel index](https://download.pytorch.org/whl/cpu/torch/)

A Docker smoke test used a CNN checkpoint trained on synthetic API sequences. The first alert fired on observation one of 21. SHA-256 checks showed 21 modified fixtures in monitor-only mode and one in enforcement mode. The offline replay produced the same first alert and agreed within `2.11e-10` on every score. [Model smoke-test result](model-smoke-result.json)
