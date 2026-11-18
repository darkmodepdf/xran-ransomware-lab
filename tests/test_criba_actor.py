import io
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from prepare_context_criba import read_prefix


class CribaActorTests(unittest.TestCase):
    def test_task_projection_separates_threads_in_one_process(self):
        rows = [{'system_call_name': 'write', 'call_timestamp': index + 1,
                 'return_timestamp': index + 2, 'return_value': 4,
                 'pid': 42, 'tid': 101 + index, 'fdata': {'file_path': '/work/file'}}
                for index in range(2)]
        content = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
        pid_audit, tid_audit = {}, {}
        process, process_times, count = read_prefix(io.BytesIO(content), 'pid', pid_audit)
        tasks, task_times, task_count = read_prefix(io.BytesIO(content), 'tid', tid_audit)
        self.assertEqual([event['actor'] for event in process], ['0', '0'])
        self.assertEqual([event['actor'] for event in tasks], ['0', '1'])
        self.assertEqual((process_times, count), (task_times, task_count))
        self.assertEqual(tid_audit, {'actor_field': 'tid', 'unique_processes': 1,
                                     'unique_tasks': 2, 'missing_actor_events': 0})
        for pid_event, tid_event in zip(process, tasks):
            self.assertEqual({key: value for key, value in pid_event.items() if key != 'actor'},
                             {key: value for key, value in tid_event.items() if key != 'actor'})


if __name__ == '__main__':
    unittest.main()
