"""Measured dashboard history, milestones and retained first-alert semantics."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from raneval.windows_stream import FEATURES,HORIZON,Model,Router,canonical

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dashboard_server',ROOT/'demo/windows_streaming/server.py')
server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)


class DashboardStateTests(unittest.TestCase):
    def state(self):
        state=server.State(ROOT/'missing-test-model.json')
        payload=dict(schema='windows-mil-linear-v1',event_schema='windows-event-v1',features=list(FEATURES),horizon=HORIZON,weights=[0.]*len(FEATURES),bias=10.,threshold=.7)
        state.router=Router(Model(dict(payload=payload,sha256=hashlib.sha256(canonical(payload)).hexdigest())))
        state.update(dict(agent_id='test'))
        return state

    def job(self,state):
        return state.control(dict(action='start',kind='benign'))['job']

    def event(self,job,seq=1,actor='one'):
        return dict(schema='windows-event-v1',job=job,actor=actor,pid=42,incarnation='born',seq=seq,op='write',outcome='success',target='t',target_kind='file_candidate')

    def evidence(self,job,valid):
        return dict(job=job,file='fixture-0.jsonl',sha256='a'*64,baseline_sha256='b'*64,valid=valid,changed=True,actor='one',bytes=26)

    def test_actual_history_first_alert_retained_and_no_kind_override(self):
        state=self.state();job=self.job(state)
        state.update(dict(agent_id='test',event=self.event(job),evidence=[self.evidence(job,False)]))
        state.router.model.score=lambda x:.1
        state.update(dict(agent_id='test',event=self.event(job,2),evidence=[self.evidence(job,False)]))
        snapshot=state.snapshot();actor=snapshot['actors'][0]
        self.assertEqual(actor['kind'],'benign')
        self.assertTrue(actor['ever_alert']);self.assertFalse(actor['alert'])
        self.assertEqual(actor['first_alert_seq'],1)
        self.assertEqual(actor['invalid_files_at_first_alert'],1)
        self.assertGreater(actor['peak_score'],.99)
        self.assertEqual([(p['seq'],p['score']) for p in actor['history']],[(1,actor['peak_score']),(2,.1)])
        self.assertEqual([m['type'] for m in snapshot['activity']],['file_invalid','model_alert'])

    def test_validity_and_model_decision_independent_and_first_restore_only(self):
        state=self.state();state.router.model.score=lambda x:.1;job=self.job(state)
        for seq,valid in enumerate((False,True,False,True),1):
            state.update(dict(agent_id='test',event=self.event(job,seq),evidence=[self.evidence(job,valid)]))
        snap=state.snapshot()
        self.assertFalse(snap['actors'][0]['ever_alert'])
        self.assertEqual([m['type'] for m in snap['activity']],['file_invalid','file_restored'])
        self.assertTrue(snap['files'][0]['valid'])

    def test_bounded_histories_and_unavailable_score_not_fabricated(self):
        state=self.state();job=self.job(state);state.router.model.score=lambda x:None
        for seq in range(1,601):state.update(dict(agent_id='test',event=self.event(job,seq)))
        history=state.snapshot()['actors'][0]['history']
        self.assertEqual(len(history),512);self.assertEqual(history[0]['seq'],89)
        self.assertTrue(all(p['score'] is None for p in history));self.assertFalse(state.actors['one']['ever_alert'])
        for actor in range(8):state.update(dict(agent_id='test',event=self.event(job,actor='actor'+str(actor))))
        self.assertEqual(len(state.histories),8)
        self.assertEqual(next(a for a in state.snapshot()['actors'] if a['actor']=='one')['history'],[])
        for i in range(100):state.milestone('worker_completed',job,'Completed')
        self.assertEqual(len(state.activity),96)

    def test_status_milestones_idempotent_bad_evidence_atomic(self):
        state=self.state();job=self.job(state)
        for status in ('running','running','completed','completed'):
            state.update(dict(agent_id='test',job_status=dict(job=job,status=status)))
        self.assertEqual([m['type'] for m in state.activity],['worker_started','worker_completed'])
        before=state.snapshot()
        with self.assertRaises(ValueError):state.update(dict(agent_id='test',event=self.event(job),evidence=[{'bad':True}]))
        self.assertEqual(state.snapshot(),before)


if __name__=='__main__':unittest.main()
