"""Actual owned-fixture campaigns: measured I/O, hard negatives, and same-PID onset."""
import importlib.util
import os
from pathlib import Path
import queue
import random
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native_campaign_agent',ROOT/'demo/windows_streaming/agent.py')
agentmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(agentmod)


class ConfigurationTests(unittest.TestCase):
    def test_rejects_arbitrary_campaign_inputs(self):
        for value in ({'path':'C:/'},{'variant':'shell'},{'cycles':0},{'warmup':4},{'seed':True},{'delay':float('nan')},{'profile':'arbitrary'}):
            with self.assertRaises(ValueError):agentmod.campaign_config('benign',value)

    def test_seeded_benign_fixtures_include_high_entropy_valid_binary(self):
        fixtures=[agentmod.fixture_bytes(random.Random(seed)) for seed in range(24)]
        self.assertTrue(all(agentmod.valid(f) for f in fixtures))
        binary=[f for f in fixtures if f.startswith(agentmod.BINARY_MAGIC)]
        self.assertTrue(binary)
        self.assertGreater(max(map(agentmod.entropy,binary)),7.5)
        changed=bytearray(binary[0]);changed[-1]^=1
        self.assertFalse(agentmod.valid(changed))

    def test_profiles_are_shared_valid_initializers(self):
        for profile in agentmod.PROFILES:
            self.assertEqual(agentmod.campaign_config('benign',{'profile':profile})['profile'],profile)
            self.assertEqual(agentmod.campaign_config('destructive',{'profile':profile})['profile'],profile)
            self.assertTrue(all(agentmod.valid(agentmod.fixture_bytes(random.Random(seed),profile)) for seed in range(12)))
        self.assertEqual(agentmod.replacement_bytes(random.Random(0),25,'compact'),b'INVALID GENERATED FIXTURE\n')


@unittest.skipUnless(os.name=='nt','actual native Windows operations required')
class NativeCampaignTests(unittest.TestCase):
    def run_campaign(self,kind,variant,seed=3,cycles=2,warmup=0,profile='mixed'):
        agent=agentmod.Agent('http://127.0.0.1:8767','a'*64);updates=[]
        agent.update=lambda **data:updates.append(data)
        job=uuid.uuid4().hex;root=None
        try:
            agent.start(dict(job=job,kind=kind,campaign=dict(variant=variant,seed=seed,cycles=cycles,warmup=warmup,delay=0,profile=profile)))
            root=agent.jobs[job]['root'];deadline=time.monotonic()+15
            while agent.jobs and time.monotonic()<deadline:
                try:owner,payload=agent.events.get(timeout=.5)
                except queue.Empty:continue
                agent.consume(owner,payload)
            self.assertFalse(agent.jobs)
            self.assertFalse(root.exists())
            final=next(u for u in reversed(updates) if u.get('job_status',{}).get('job')==job)
            self.assertEqual(final['job_status']['status'],'completed')
            return [u['event'] for u in updates if 'event' in u],final['evidence'],updates
        finally:agent.close()

    def test_actual_requested_completed_offsets_and_post_flush_sizes(self):
        events,files,updates=self.run_campaign('destructive','truncate')
        reads=[e for e in events if e['op']=='read']
        self.assertTrue(all(e['requested_bytes']==16384 and e['completed_bytes']==e['file_size_before']<16384 for e in reads))
        for update in updates:
            event=update.get('event')
            if not event:continue
            item=next(f for f in update['evidence'] if agentmod.digest((f['job']+':'+f['file']).encode())==event['target'])
            self.assertEqual(item['bytes'],event['file_size_after'])
            if event['op']=='write':
                self.assertEqual(event['requested_bytes'],event['completed_bytes'])
                self.assertEqual(event['file_offset_after'],event['byte_offset']+event['completed_bytes'])
                self.assertGreaterEqual(event['entropy_after'],0)
                self.assertTrue(0<=event['changed_byte_fraction']<=1)
        self.assertTrue(all(not f['valid'] for f in files))

    def test_benign_overwrites_and_truncations_are_real_hard_negatives(self):
        for variant in ('save','rotate','copy','append'):
            events,files,_=self.run_campaign('benign',variant)
            self.assertTrue(all(f['valid'] for f in files),variant)
            self.assertTrue(any(e['op']=='write' and e['byte_offset']==0 for e in events))
            if variant=='rotate':
                self.assertTrue(any(e['op']=='resize' and e['file_size_after']==0 for e in events))
            self.assertTrue(any(e.get('entropy_before',0) is not None and (e.get('entropy_before') or 0)>7.5 for e in events))

    def test_delayed_destructive_onset_preserves_same_actor_and_valid_warmup(self):
        events,files,updates=self.run_campaign('destructive','overwrite',cycles=3,warmup=1)
        self.assertEqual(len({(e['actor'],e['pid'],e['incarnation']) for e in events}),1)
        warm=[u for u in updates if u.get('event',{}).get('seq',999)<=24]
        self.assertEqual(len(warm),24)
        self.assertTrue(all(f['valid'] for u in warm for f in u['evidence']))
        self.assertTrue(all(not f['valid'] for f in files))
        self.assertTrue(all(not any(k in e for k in ('variant','kind','warmup','valid','seed')) for e in events))

    def test_low_entropy_profiles_keep_benign_valid_and_damage_destructive(self):
        for profile in ('compact','repetitive','structured'):
            for kind,variants in agentmod.VARIANTS.items():
                for variant in variants:
                    events,files,_=self.run_campaign(kind,variant,cycles=2,profile=profile)
                    self.assertTrue(all(f['valid']==(kind=='benign') for f in files),(profile,kind,variant))
                    for event in events:
                        self.assertNotIn('profile',event)
                        self.assertLessEqual(event['file_size_after'],16384)
                        if event['op']=='write':self.assertEqual(event['file_offset_after'],event['byte_offset']+event['completed_bytes'])


if __name__=='__main__':unittest.main()
