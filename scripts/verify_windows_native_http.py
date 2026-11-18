"""Actual native workers -> authenticated HTTP -> shipped model parity and evidence.

Run against an isolated lab service, with no other agent connected. Credentials are
read from a local file and never printed. No training or threshold changes occur.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import queue
import sys
import time
from http.client import RemoteDisconnected
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from raneval.windows_stream import Model, Router


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    credentials = json.loads(args.credentials.read_text())
    control = credentials.get('control_token') or credentials.get('control')
    token = credentials.get('agent_token') or credentials.get('agent')
    if not control or not token:
        raise ValueError('Expected control_token and agent_token credential fields')
    spec = importlib.util.spec_from_file_location('http_native_agent', ROOT / 'demo/windows_streaming/agent.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    model = Model(ROOT / 'demo/windows_streaming/native-model.json')
    router = Router(model)
    agent = module.Agent('http://127.0.0.1:8767', token)

    def request(path, data=None, agent_role=False):
        body = json.dumps(data).encode() if data is not None else None
        req = Request(agent.url + path, data=body, headers={
            'Authorization': 'Bearer ' + (token if agent_role else control),
            'Content-Type': 'application/json'})
        with urlopen(req, timeout=10) as response:
            return json.load(response)

    results = []
    profiles = {}
    max_error = 0.
    calls = 0

    def update(**data):
        nonlocal max_error, calls
        result = request('/api/agent/update', dict(agent_id=agent.id, **data), True)
        if 'event' in data:
            event = data['event']
            expected = router.add(event)
            state = request('/api/state')
            measured = next(a for a in state['actors'] if a['actor'] == event['actor'])
            if expected['score'] is None:
                assert measured['score'] is None and not measured['alert']
            else:
                max_error = max(max_error, abs(expected['score'] - measured['score']))
                assert expected['alert'] == measured['alert']
            profile = profiles[event['job']]
            profile['events'] += 1
            invalid = sum(not f['valid'] for f in data.get('evidence', []))
            if invalid and profile['first_invalid_seq'] is None:
                profile['first_invalid_seq'] = event['seq']
            if measured['alert'] and profile['first_alert_seq'] is None:
                profile.update(first_alert_seq=event['seq'], invalid_files_at_first_alert=invalid)
            if measured['score'] is not None:
                profile['peak_score'] = max(profile['peak_score'], measured['score'])
            calls += 1
        if data.get('job_status', {}).get('status') in ('completed', 'failed', 'stopped'):
            profile = profiles[data['job_status']['job']]
            profile['status'] = data['job_status']['status']
            profile['final_invalid_files'] = sum(not f['valid'] for f in data.get('evidence', []))
        return result

    agent.update = update
    started = time.perf_counter()
    roots = []
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                health = request('/api/health')
                if not health.get('model_available'):
                    raise RuntimeError('Service model is unavailable')
                break
            except (URLError, RemoteDisconnected, ConnectionResetError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
        agent.update()
        for pair, configuration in (
            ('default_concurrent', {'benign': None, 'destructive': None}),
            ('delayed_concurrent', {
                'benign': dict(variant='save', seed=192731, cycles=5, delay=.002, warmup=0),
                'destructive': dict(variant='overwrite', seed=827391, cycles=5, delay=.002, warmup=2)})):
            for kind in configuration:
                job = request('/api/control', dict(action='start', kind=kind))['job']
                profiles[job] = dict(pair=pair, kind=kind, events=0, peak_score=0.,
                    first_invalid_seq=None, first_alert_seq=None, invalid_files_at_first_alert=None)
            commands = request('/api/agent/next', agent_role=True)['commands']
            for command in commands:
                if configuration[command['kind']] is not None:
                    command['campaign'] = configuration[command['kind']]
                agent.start(command)
                roots.append(agent.jobs[command['job']]['root'])
            deadline = time.monotonic() + 60
            while agent.jobs and time.monotonic() < deadline:
                try:
                    job, payload = agent.events.get(timeout=.5)
                except queue.Empty:
                    continue
                agent.consume(job, payload)
            if agent.jobs:
                raise RuntimeError('Native HTTP workers did not finish')
            results.extend(p for p in profiles.values() if p['pair'] == pair)
        assert max_error < 1e-12
        assert all(p['status'] == 'completed' for p in results)
        assert all(not root.exists() for root in roots)
        state = request('/api/state')
        report = dict(model_sha256=json.loads((ROOT / 'demo/windows_streaming/native-model.json').read_text())['sha256'],
            model_schema=state['model_schema'], threshold=state['threshold'],
            max_runtime_http_score_error=max_error, scored_events=calls,
            wall_seconds=time.perf_counter() - started, owned_roots_removed=True,
            profiles=results, errors=state['errors'])
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    finally:
        agent.close()


if __name__ == '__main__':
    main()
