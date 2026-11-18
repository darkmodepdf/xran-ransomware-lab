import gzip,json,unittest,tempfile,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from audit_en2025_streaming import project

class ProjectionTests(unittest.TestCase):
    def test_stream_preserves_call_order_and_process_incarnations(self):
        processes=[]
        for born in ('a','b'):
            processes.append(dict(process_id=5,parent_id=1,first_seen=born,calls=[dict(api='Unprojected',timestamp='same',repeated=2),dict(api='NtWriteFile',thread_id='7',timestamp='same',status=True,**{'return':'0x103'},arguments=[{'name':'Length','value':'42'},{'name':'HandleName','value':'C:\\generated.txt'}])]))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'report.json'; p.write_text(json.dumps({'behavior':{'processes':processes}}))
            import io
            out=io.StringIO(); result=project(p,'capture',out)
            rows=[json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(result['counts']['calls'],4)
        self.assertEqual(result['counts']['duplicate_pid_entries'],1)
        self.assertEqual(len(rows),2); self.assertNotEqual(rows[0]['actor'],rows[1]['actor'])
        self.assertEqual(rows[0]['observed_index'],2); self.assertEqual(rows[0]['seq'],1)
        self.assertEqual(rows[0]['requested_bytes'],42); self.assertIsNone(rows[0]['completed_bytes'])
        self.assertEqual(result['counts']['repeat_ambiguous_calls'],2)
