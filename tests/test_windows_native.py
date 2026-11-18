import hashlib
import math
import unittest
from raneval.windows_native import FEATURES,HORIZON,History
from raneval.windows_stream import Model,Router,canonical


def event(seq=1,op='write',actor='native'):
    return dict(schema='windows-event-v1',actor=actor,pid=42,incarnation='born',seq=seq,op=op,outcome='success',target='target',target_kind='file_candidate',byte_offset=0,file_size_before=100,file_size_after=100,file_offset_after=100,requested_bytes=100,completed_bytes=100,entropy_before=4.,entropy_after=6.,changed_byte_fraction=.8)


def model():
    payload=dict(schema='windows-native-forest-v2',event_schema='windows-event-v1',features=list(FEATURES),horizon=HORIZON,threshold=.5,trees=[[[4,.5,1,2,0],[-1,0,-1,-1,.2],[-1,0,-1,-1,.8]]])
    return Model(dict(payload=payload,sha256=hashlib.sha256(canonical(payload)).hexdigest()))


class NativeTests(unittest.TestCase):
    def test_operation_features_and_order(self):
        h=History();x=h.add(event(op='read'));x=h.add(event(seq=2))
        values=dict(zip(FEATURES,x));self.assertEqual(values['overwrite_fraction'],.5);self.assertEqual(values['read_then_write_fraction'],.5);self.assertEqual(values['mean_write_coverage'],1)
        append=dict(event(),byte_offset=100,file_offset_after=200,file_size_after=200)
        values=dict(zip(FEATURES,History().add(append)));self.assertEqual(values['append_fraction'],1);self.assertEqual(values['overwrite_fraction'],0)
        truncate=dict(event(op='resize'),file_size_after=0,file_offset_after=0)
        values=dict(zip(FEATURES,History().add(truncate)));self.assertEqual(values['truncate_fraction'],1)
    def test_replacement_size_keeps_original_before_truncation_and_smaller_saves(self):
        read=dict(event(op='read'),file_size_before=85,file_size_after=85,completed_bytes=85,requested_bytes=85,file_offset_after=85)
        resize=dict(event(seq=2,op='resize'),file_size_before=85,file_size_after=0,byte_offset=0,file_offset_after=0,requested_bytes=None,completed_bytes=None)
        def replacement(size):
            h=History();h.add(read);h.add(resize)
            write=dict(event(seq=3),file_size_before=0,file_size_after=size,completed_bytes=size,requested_bytes=size,file_offset_after=size)
            return dict(zip(FEATURES,h.add(write)))
        small=replacement(25);restored=replacement(85)
        self.assertAlmostEqual(small['mean_replacement_size_ratio'],25/85)
        self.assertAlmostEqual(small['mean_missing_original_coverage'],60/85)
        self.assertEqual(small['mean_changed_original_coverage'],1)
        self.assertEqual(restored['mean_replacement_size_ratio'],1)
        self.assertEqual(restored['mean_missing_original_coverage'],0)
        h=History();h.add(read)
        h.add(dict(event(seq=2),file_size_before=85,file_size_after=85,completed_bytes=25,requested_bytes=25,file_offset_after=25))
        values=dict(zip(FEATURES,h.add(dict(resize,seq=3,file_size_after=25))))
        self.assertAlmostEqual(values['mean_replacement_size_ratio'],25/85)
        self.assertAlmostEqual(values['mean_missing_original_coverage'],60/85)

    def test_zero_byte_write_beyond_eof_is_valid_but_positive_write_is_rejected(self):
        from raneval.windows_native_v1 import History as HistoryV1
        zero=dict(event(),byte_offset=200,completed_bytes=0,file_offset_after=200)
        for history_type in (History,HistoryV1):
            self.assertIsNotNone(history_type().add(zero))
            positive=dict(zero,completed_bytes=1,file_offset_after=201)
            with self.assertRaisesRegex(ValueError,'write exceeds observed size'):history_type().add(positive)

    def test_zero_byte_read_beyond_eof_is_valid_but_positive_read_is_rejected(self):
        zero=dict(event(op='read'),byte_offset=200,completed_bytes=0,file_offset_after=200)
        self.assertIsNotNone(History().add(zero))
        positive=dict(zero,completed_bytes=1,file_offset_after=201)
        with self.assertRaisesRegex(ValueError,'read exceeds observed size'):History().add(positive)

    def test_names_labels_validity_and_entropy_level_are_excluded(self):
        original=event();changed=dict(original,actor='other',target='other',job='destructive',kind='destructive',valid=False,marker='evil',entropy_before=5.,entropy_after=7.)
        self.assertEqual(History().add(original),History().add(changed))
    def test_missing_is_unavailable_without_synthesized_features(self):
        r=Router(model());missing=event();missing.pop('file_size_before')
        result=r.add(missing);self.assertIsNone(result['score']);self.assertFalse(result['alert']);self.assertFalse(result['score_available'])
        self.assertIn('enriched',result['score_unavailable_reason'])
        for i in range(2,HORIZON+2):result=r.add(event(i))
        self.assertIsNotNone(result['score']);self.assertEqual(len(r.actors['native'].events),HORIZON)
    def test_invalid_measurements_do_not_advance_history(self):
        h=History();h.add(event())
        for change in [dict(byte_offset=-1),dict(completed_bytes=101),dict(file_offset_after=0),dict(entropy_after=math.inf),dict(file_size_after=None,byte_offset=-1),dict(changed_byte_fraction=1.1)]:
            with self.assertRaises(ValueError):h.add(dict(event(seq=2),**change))
            self.assertEqual(h.seq,1)
        for change in [dict(pid=43),dict(incarnation='reborn')]:
            with self.assertRaises(ValueError):h.add(dict(event(seq=2),**change))
    def test_interleaved_matches_isolated_and_tree_dispatch(self):
        m=model();isolated=Router(m);expected=[isolated.add(event(i))['score'] for i in range(1,150)]
        interleaved=Router(m)
        for i,score in enumerate(expected,1):
            interleaved.add(event(i,actor='unrelated'));self.assertEqual(interleaved.add(event(i))['score'],score)
        self.assertEqual(expected[0],.8)
    def test_malformed_tree_rejected(self):
        p=model().payload
        for trees in [[],[[[0,.5,0,1,.5],[-1,0,-1,-1,1]]],[[[-1,0,-1,-1,math.nan]]]]:
            bad=dict(p,trees=trees)
            with self.assertRaises(ValueError):Model(dict(payload=bad,sha256=hashlib.sha256(canonical(bad)).hexdigest()))

if __name__=='__main__':unittest.main()
