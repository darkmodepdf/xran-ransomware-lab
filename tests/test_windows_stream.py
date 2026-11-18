import hashlib,random,unittest
from pathlib import Path
from raneval.windows_stream import Model,Router,History,FEATURES,HORIZON,canonical

def model():
    p=dict(schema='windows-mil-linear-v1',event_schema='windows-event-v1',features=list(FEATURES),horizon=HORIZON,weights=[.03*(i+1) for i in range(len(FEATURES))],bias=-1.,threshold=.7)
    return Model(dict(payload=p,sha256=hashlib.sha256(canonical(p)).hexdigest()))
def event(actor='one',seq=1,op='write'):
    return dict(schema='windows-event-v1',actor=actor,pid=42,incarnation='birth',seq=seq,op=op,outcome='success',target='a',target_kind='file_candidate')

class RuntimeTests(unittest.TestCase):
    def test_actor_identity_changes_rejected_without_history_mutation(self):
        r=Router(model());r.add(event())
        history=r.actors['one'];before=history.vector()
        for changed in ({'pid':43},{'incarnation':'another-birth'}):
            with self.assertRaisesRegex(ValueError,'PID/incarnation'):
                r.add(dict(event(seq=2),**changed))
            self.assertEqual(history.seq,1);self.assertEqual(len(history.events),1)
            self.assertEqual(history.vector(),before);self.assertEqual(history.identity,(42,'birth'))
        valid=r.add(event(seq=2));self.assertEqual(valid['seq'],2)
    def test_interleaving_equals_isolated_scores_and_bounded_history(self):
        streams={actor:[event(actor,i,('open','read','write','close')[i%4]) for i in range(1,301)] for actor in ('a','b','c')}
        isolated={}
        for a,events in streams.items():
            router=Router(model());isolated[a]=[router.add(e)['score'] for e in events]
        router=Router(model());positions={a:0 for a in streams};rng=random.Random(42)
        while any(positions[a]<300 for a in streams):
            a=rng.choice([a for a in streams if positions[a]<300]);i=positions[a];out=router.add(streams[a][i]);self.assertEqual(out['score'],isolated[a][i]);positions[a]+=1
        self.assertTrue(all(len(h.events)==128 and h.evictions==172 for h in router.actors.values()))
    def test_identity_gaps_capacity_and_unavailable(self):
        r=Router(None,max_actors=1);out=r.add(event());self.assertIsNone(out['score']);self.assertFalse(out['alert'])
        for e in (event(seq=3),event('two'),dict(event(seq=2),pid=None)):
            with self.assertRaises(ValueError):r.add(e)
        self.assertEqual(r.actors['one'].seq,1);self.assertEqual(r.rejected,3)
    def test_oracle_and_names_do_not_change_features(self):
        e=event();modified=dict(e,scenario='destructive',oracle=True,path='C:/secrets',name='ransomware')
        self.assertEqual(History().add(e),History().add(modified))
    def test_model_hash_schema_and_nonfinite_rejected(self):
        p=model().payload
        for change in ({'weights':[0.]},{'bias':float('inf')},{'horizon':64}):
            altered=dict(p,**change)
            with self.assertRaises(ValueError):Model({'payload':altered,'sha256':hashlib.sha256(canonical(altered)).hexdigest()})
        with self.assertRaises(ValueError):Model({'payload':p,'sha256':'wrong'})
    def test_export_replay_matches_shipped_weights(self):
        path=Path(__file__).resolve().parents[1]/'demo/windows_streaming/model.json';r=Router(Model(path))
        scores=[r.add(event(seq=i))['score'] for i in range(1,20)];loaded=Router(Model(path))
        self.assertEqual(scores,[loaded.add(event(seq=i))['score'] for i in range(1,20)])
