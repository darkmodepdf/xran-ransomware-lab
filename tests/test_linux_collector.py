import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'capture_linux_benign.py'
SPEC = importlib.util.spec_from_file_location('collector', SCRIPT)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class LinuxCollectorTests(unittest.TestCase):
    def test_overlap_has_identical_observed_projection_live_and_offline(self):
        lines = [
            '11 100.000000 write(3</work/input>, "", 1 <unfinished ...>\n',
            '22 100.000010 close(4</work/other>) = 0 <0.000001>\n',
            '11 100.000012 <... write resumed>) = 1 <0.000009>\n',
        ]
        lines.extend(f'11 101.{index:06} close(3</work/input>) = 0 <0.000001>\n'
                     for index in range(120))
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / 'trace.txt'
            raw.write_text(''.join(lines), encoding='utf-8')
            workspace = Path('/work')
            live = list(collector.observed_events(collector.syscall_records(lines, 'fixture'),
                                                  collector.CaptureContext(workspace)))
            offline = collector.read_completed(raw, collector.CaptureContext(workspace), order='observed')
            legacy = collector.read_completed(raw, collector.CaptureContext(workspace))
        self.assertEqual(live, offline[4])
        self.assertEqual(offline[0][:2], ['close', 'write'])
        self.assertEqual(legacy[0][:2], ['write', 'close'])
        self.assertGreater(live[0]['completion_time_ns'], live[1]['completion_time_ns'])
        self.assertEqual([row['time_ms'] for row in live[:2]], [0.0, 0.0])
        self.assertEqual(live[1]['sequence'], 2)
        self.assertEqual(live[1]['bytes_changed'], 1)

    def test_live_default_continues_beyond_benchmark_cap(self):
        lines = [f'11 101.{index:06} close(3</work/input>) = 0 <0.000001>\n'
                 for index in range(collector.CAP + 2)]
        records = collector.syscall_records(lines, 'fixture')
        rows = list(collector.observed_events(records, collector.CaptureContext(Path('/work'))))
        self.assertEqual(len(rows), collector.CAP + 2)
        self.assertEqual(rows[-1]['sequence'], collector.CAP + 2)

    def test_bounded_live_output_still_drains_and_validates_remaining_input(self):
        lines = ['11 100.000000 close(3</work/input>) = 0 <0.000001>\n',
                 '11 101.000000 write(3</work/input>, "", 1 <unfinished ...>\n']
        events = collector.observed_events(collector.syscall_records(lines, 'fixture'),
                                            collector.CaptureContext(Path('/work')), max_events=1)
        self.assertEqual(next(events)['op'], 'close')
        with self.assertRaisesRegex(ValueError, 'Incomplete syscalls'):
            list(events)


if __name__ == '__main__':
    unittest.main()
