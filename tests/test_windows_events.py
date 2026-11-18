import unittest
from collections import Counter
from raneval.windows_events import Projector, outcome

class AdapterTests(unittest.TestCase):
    def test_failed_and_pending_rename_preserve_binding(self):
        p=Projector('c',1,{'process_id':12})
        opened=p.call({'api':'NtOpenFile','return':'0','arguments':{'FileHandle':'8','FileName':'C:\\original.txt'}},1)
        for result in ('0xc0000022','0x103'):
            p.call({'api':'NtSetInformationFile','return':result,'arguments':{'FileHandle':'8','FileInformationClass':'10'}},2)
            read=p.call({'api':'NtReadFile','return':'0','arguments':{'FileHandle':'8'}},3)
            self.assertEqual(read['target'],opened['target'])
    def test_unnamed_successful_reused_handle_is_unknown(self):
        p=Projector('c',1,{'process_id':12})
        p.call({'api':'NtOpenFile','return':'0','arguments':{'FileHandle':'8','FileName':'C:\\old.txt'}},1)
        reopened=p.call({'api':'NtOpenFile','return':'0','arguments':{'FileHandle':'8'}},2)
        read=p.call({'api':'NtReadFile','return':'0','arguments':{'FileHandle':'8'}},3)
        self.assertIsNone(reopened['target']);self.assertIsNone(read['target'])
        self.assertEqual(reopened['target_kind'],'unknown')
    def test_pending_and_requested_are_not_completed(self):
        p=Projector('c',1,{'process_id':12})
        e=p.call({'api':'NtWriteFile','return':'0x103','status':True,'arguments':{'Length':'2048','HandleName':'C:\\a.txt'}},1)
        self.assertEqual(e['outcome'],'pending'); self.assertIsNone(e['completed_bytes'])
        self.assertEqual(outcome('NtWriteFile',True,'0xffffffffc0000022'),'failure')
    def test_handle_reuse_close_and_unknown_rename(self):
        c=Counter(); p=Projector('c',1,{},c)
        def emit(api,args): return p.call(dict(api=api,arguments=args,return_='unused',**{'return':'0'}),1)
        emit('NtCreateFile',{'FileHandle':'0x20','FileName':'C:\\a.txt'})
        old=emit('NtReadFile',{'FileHandle':'32'})['target']
        emit('NtCreateFile',{'FileHandle':'32','FileName':'C:\\b.txt'})
        self.assertNotEqual(old,emit('NtReadFile',{'FileHandle':'32'})['target'])
        emit('NtSetInformationFile',{'FileHandle':'32','FileInformationClass':'10'})
        self.assertIsNone(emit('NtReadFile',{'FileHandle':'32'})['target'])
        emit('NtClose',{'Handle':'32'})
        self.assertEqual(c['handle_rebind_before_close'],1)

if __name__=='__main__': unittest.main()

class BoundaryTests(unittest.TestCase):
    def test_failed_close_does_not_retire_other_process_handle(self):
        p=Projector('c',1,{'process_id':1}); other=Projector('c',2,{'process_id':2})
        p.call({'api':'NtOpenFile','return':'0','arguments':{'FileHandle':'8','FileName':'C:\\one.txt'}},1)
        p.call({'api':'NtClose','return':'0xc0000008','arguments':{'Handle':'8'}},2)
        e=p.call({'api':'NtReadFile','return':'0','arguments':{'FileHandle':'8'}},3)
        unknown=other.call({'api':'NtReadFile','return':'0','arguments':{'FileHandle':'8'}},1)
        self.assertIsNotNone(e['target']); self.assertIsNone(unknown['target'])
    def test_handle_table_overflow_is_visible(self):
        c=Counter(); p=Projector('c',1,{},c)
        for i in range(1,4098):
            p.call({'api':'NtOpenFile','return':'0','arguments':{'FileHandle':str(i),'FileName':'C:\\f'+str(i)}},i)
        self.assertEqual(len(p.handles),4096)
        self.assertEqual(c['handle_table_evictions'],1)
        self.assertNotIn(1,p.handles)
    def test_device_write_and_informational_status_stay_distinct(self):
        p=Projector('c',1,{})
        e=p.call({'api':'NtWriteFile','return':'0','arguments':{'HandleName':'\\Device\\ConDrv','Length':'99'}},1)
        self.assertEqual(e['target_kind'],'nonfile'); self.assertIsNone(e['completed_bytes'])
        self.assertEqual(outcome('NtOpenFile',True,'0x40000000'),'unknown')
