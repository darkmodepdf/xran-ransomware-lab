import importlib.util,json,os,queue,sys,threading,time,unittest,uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
servermod=load('windows_lab_server','demo/windows_streaming/server.py')
agentmod=load('windows_lab_agent','demo/windows_streaming/agent.py')

class HttpTests(unittest.TestCase):
    def setUp(self):
        self.control='c'*64;self.agent='a'*64;self.server=servermod.make_server('127.0.0.1',0,ROOT/'demo/windows_streaming/model.json',self.control,self.agent);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.url='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def request(self,path,data=None,token=None,origin=None,raw=None):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        if origin:headers['Origin']=origin
        body=raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        try:
            with urlopen(Request(self.url+path,data=body,headers=headers),timeout=5) as r:return r.status,json.load(r)
        except HTTPError as e:return e.code,json.load(e)
    def test_auth_roles_origin_size_and_allowlist(self):
        self.assertEqual(self.request('/api/state')[0],401)
        self.assertEqual(self.request('/api/agent/next',token=self.control)[0],401)
        self.assertEqual(self.request('/api/state',token=self.control,origin='http://evil.example')[0],403)
        self.assertEqual(self.request('/api/control',raw=b'x'*65537,token=self.control)[0],413)
        self.assertEqual(self.request('/api/agent/update',dict(agent_id='test'),self.agent)[0],200)
        for data in ({'action':'start','kind':'arbitrary'},{'action':'start','kind':'benign','path':'C:/host'},{'action':'command','command':'echo no'}):self.assertEqual(self.request('/api/control',data,self.control)[0],400)
        code,job=self.request('/api/control',dict(action='start',kind='benign'),self.control);self.assertEqual(code,200)
        _,queue=self.request('/api/agent/next',token=self.agent);self.assertEqual(queue['commands'][0]['job'],job['job'])
        for i in range(3):self.assertEqual(self.request('/api/control',dict(action='start',kind='benign'),self.control)[0],200)
        self.assertEqual(self.request('/api/control',dict(action='start',kind='benign'),self.control)[0],400)
    def test_oversized_boundary_returns_413_without_state_change(self):
        self.assertEqual(self.request('/api/agent/update',dict(agent_id='test'),self.agent)[0],200)
        before=self.server.state.snapshot()
        with patch.object(self.server.state,'control',wraps=self.server.state.control) as control:
            code,body=self.request('/api/control',raw=b'x'*65537,token=self.control)
            self.assertEqual(code,413);self.assertIn('65536',body['error'])
            control.assert_not_called()
        self.assertEqual(self.server.state.snapshot(),before)
        self.assertEqual(len(self.server.state.commands),0)
        code,health=self.request('/api/health')
        self.assertEqual(code,200);self.assertTrue(health['ok'])
        code,state=self.request('/api/state',token=self.control)
        self.assertEqual(code,200);self.assertEqual(state['jobs'],[])
    def test_offline_no_model_and_atomic_bad_evidence(self):
        self.assertEqual(self.request('/api/control',dict(action='start',kind='benign'),self.control)[0],400)
        state=servermod.State(ROOT/'missing-model-file');self.assertFalse(state.snapshot()['model_available']);self.assertIsNotNone(state.snapshot()['model_error'])
        self.request('/api/agent/update',dict(agent_id='test'),self.agent);_,job=self.request('/api/control',dict(action='start',kind='benign'),self.control)
        event=dict(schema='windows-event-v1',actor='actor',pid=3,incarnation='born',seq=1,op='write',outcome='success',target='x',target_kind='file_candidate',job=job['job'])
        self.assertEqual(self.request('/api/agent/update',dict(agent_id='test',event=event,evidence=[{'bad':True}]),self.agent)[0],400)
        self.assertEqual(self.server.state.router.actors,{})
        self.assertEqual(self.request('/api/agent/update',dict(agent_id='test',event=event),self.agent)[0],200)
        self.assertEqual(self.request('/api/agent/update',dict(agent_id='test',event=event),self.agent)[0],400)

@unittest.skipUnless(os.name=='nt','actual native Windows operations required')
class NativeTests(unittest.TestCase):
    def test_startup_failures_clean_partial_owned_inventory(self):
        agent=agentmod.Agent('http://127.0.0.1:8767','a'*64);agent.update=lambda **data:None
        original_write=Path.write_bytes
        for failure in ('popen','fixture_write'):
            job=uuid.uuid4().hex;root=Path(agentmod.tempfile.gettempdir()).resolve()/('windows-stream-'+job)
            def failing_write(path,data):
                if path.name=='fixture-2.jsonl':
                    original_write(path,b'partial')
                    raise OSError('injected fixture failure')
                return original_write(path,data)
            try:
                if failure=='popen':
                    with patch.object(agentmod.subprocess,'Popen',side_effect=OSError('injected Popen failure')):
                        with self.assertRaisesRegex(OSError,'Popen'):agent.start(dict(kind='benign',job=job))
                else:
                    with patch.object(Path,'write_bytes',failing_write):
                        with self.assertRaisesRegex(OSError,'fixture'):agent.start(dict(kind='benign',job=job))
                self.assertFalse(root.exists());self.assertNotIn(job,agent.jobs)
            finally:
                agent.close()
    def test_stop_only_owned_child_and_cleanup(self):
        agent=agentmod.Agent('http://127.0.0.1:8767','a'*64);updates=[];agent.update=lambda **data:updates.append(data)
        job=uuid.uuid4().hex
        try:
            agent.start(dict(kind='benign',job=job));root=agent.jobs[job]['root']
            queued,payload=agent.events.get(timeout=5);agent.consume(queued,payload)
            agent.stop(job);deadline=time.monotonic()+5
            while agent.jobs and time.monotonic()<deadline:
                try:queued,payload=agent.events.get(timeout=.5)
                except queue.Empty:continue
                agent.consume(queued,payload)
            self.assertFalse(agent.jobs);self.assertFalse(root.exists())
            self.assertEqual([u['job_status']['status'] for u in updates if 'job_status' in u][-1],'stopped')
        finally:agent.close()
    def test_concurrent_workers_have_independent_validity_and_owned_cleanup(self):
        agent=agentmod.Agent('http://127.0.0.1:8767','a'*64);updates=[];agent.update=lambda **data:updates.append(data)
        jobs={kind:uuid.uuid4().hex for kind in ('benign','destructive')};roots=[]
        try:
            for kind,job in jobs.items():agent.start(dict(kind=kind,job=job));roots.append(agent.jobs[job]['root'])
            deadline=time.monotonic()+25
            while agent.jobs and time.monotonic()<deadline:
                try:job,payload=agent.events.get(timeout=1)
                except queue.Empty:continue
                agent.consume(job,payload)
            self.assertFalse(agent.jobs,'bounded workers failed to complete')
            for kind,job in jobs.items():
                events=[u['event'] for u in updates if u.get('event',{}).get('job')==job]
                total=288 if kind=='benign' else 360
                self.assertEqual([e['seq'] for e in events],list(range(1,total+1)))
                self.assertTrue(all(e['pid']>0 for e in events))
                final=[u for u in updates if u.get('job_status',{}).get('job')==job][-1]
                self.assertEqual(final['job_status']['status'],'completed')
                self.assertTrue(all(f['changed'] for f in final['evidence']))
                self.assertTrue(all(f['valid']==(kind=='benign') for f in final['evidence']))
            self.assertTrue(all(not root.exists() for root in roots))
            truncations=[u for u in updates if u.get('event',{}).get('op')=='resize']
            self.assertEqual(len(truncations),72)
            for u in truncations:
                target=u['event']['target']
                touched=next(f for f in u['evidence'] if agentmod.digest((f['job']+':'+f['file']).encode())==target)
                self.assertEqual(touched['bytes'],0);self.assertFalse(touched['valid'])
        finally:agent.close()
    def test_owned_workspace_guard_rejects_host_paths(self):
        with self.assertRaises((ValueError,OSError)):agentmod.owned_root(ROOT,'b'*32,'fake')
        self.assertFalse(agentmod.valid(b'INVALID GENERATED FIXTURE\n'));self.assertTrue(agentmod.valid(agentmod.FIXTURE))
