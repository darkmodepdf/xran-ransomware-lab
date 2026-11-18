"""CAPE projection v1. Paths are evidence only; source calls are never executed."""
from collections import Counter, OrderedDict
import hashlib
import re

VERSION = 'windows-event-v1'
FILE_APIS = {'NtCreateFile':'open','NtOpenFile':'open','NtReadFile':'read','NtWriteFile':'write','NtClose':'close','NtSetInformationFile':'setinfo','DeleteFileW':'delete','DeleteFileA':'delete','MoveFileWithProgressW':'rename','MoveFileExW':'rename','NtDuplicateObject':'duplicate'}

def integer(value):
    try:
        return int(str(value), 16 if str(value).lower().startswith('0x') else 10)
    except (ValueError, TypeError):
        return None

def outcome(api, status, result):
    n = integer(result)
    if api.startswith('Nt'):
        if n is None: return 'unknown'
        n &= 0xffffffff
        if n == 0x103: return 'pending'
        return 'success' if n == 0 else ('failure' if n & 0x80000000 else 'unknown')
    return 'success' if n is not None and n != 0 else ('failure' if n == 0 else 'unknown')

def target_kind(path):
    if not path: return 'unknown'
    p = path.lower()
    if p.startswith(('\\device\\','\\\\.\\','\\??\\pipe\\')): return 'nonfile'
    if p.endswith(('\\','/')): return 'directory'
    if re.match(r'^(?:\\\?\?\\)?[a-z]:\\', p) or p.startswith('\\\\'): return 'file_candidate'
    return 'unknown'

class Projector:
    def __init__(self, capture, process_index, metadata, counts=None):
        self.actor = f'{capture}:{process_index}:{metadata.get("process_id", "missing")}:{metadata.get("first_seen", "missing")}'
        self.metadata = metadata.copy()
        self.handles = OrderedDict()
        self.counts = counts if counts is not None else Counter()
        self.seq = 0
        self.previous_time = None

    def call(self, call, observed_index):
        c = self.counts
        c['calls'] += 1
        for key in ('timestamp','thread_id','status','return','repeated'):
            c['present_' + key] += call.get(key) is not None
        stamp = call.get('timestamp')
        if stamp and self.previous_time:
            c['timestamp_ties'] += stamp == self.previous_time
            c['timestamp_regressions'] += stamp < self.previous_time
        if stamp: self.previous_time = stamp
        c['repeat_ambiguous_calls'] += bool(integer(call.get('repeated')))
        api = call.get('api', '')
        if api not in FILE_APIS: return None
        a = call.get('arguments', {})
        op = FILE_APIS[api]
        result = outcome(api, call.get('status'), call.get('return'))
        handle = integer(a.get('FileHandle', a.get('Handle')))
        explicit = a.get('FileName') or a.get('HandleName')
        path = explicit or self.handles.get(handle)
        if explicit and handle in self.handles and self.handles[handle] != explicit:
            c['handle_name_conflicts'] += 1
        if op == 'open' and result == 'success' and handle not in (None, 0):
            # A new handle incarnation cannot inherit a previous object's target.
            path = explicit or None
            c['handle_rebind_before_close'] += handle in self.handles
            if len(self.handles) >= 4096 and handle not in self.handles:
                self.handles.popitem(last=False); c['handle_table_evictions'] += 1
            self.handles[handle] = path
        if op == 'close' and result == 'success':
            c['close_unknown_handle'] += handle not in self.handles
            self.handles.pop(handle, None)
        info_class = integer(a.get('FileInformationClass'))
        if op == 'setinfo':
            c['setter_class_' + str(info_class)] += 1
            op = {10:'rename',65:'rename',13:'delete_intent',64:'delete_intent',20:'resize',19:'allocation',14:'position',4:'metadata'}.get(info_class, 'setinfo')
            # Binary structures are not safely decoded without layout/architecture evidence.
            if op == 'rename':
                c['rename_destination_unknown'] += 1
                if result == 'success' and handle in self.handles: self.handles[handle] = None
        if op == 'duplicate': c['unresolved_duplicate_handle'] += 1
        kind = target_kind(path)
        c['file_events'] += 1
        c['outcome_' + result] += 1
        c['target_' + kind] += 1
        requested = integer(a.get('Length'))
        completed = integer(a.get('NumberOfBytesTransferred'))
        if op in ('read','write'):
            c['io_calls'] += 1
            c['io_target_known'] += kind == 'file_candidate'
            c['io_completed_bytes_known'] += completed is not None and result == 'success'
        self.seq += 1
        return dict(schema=VERSION, actor=self.actor, pid=self.metadata.get('process_id'), parent_pid=self.metadata.get('parent_id'), incarnation=self.metadata.get('first_seen'), thread=call.get('thread_id'), seq=self.seq, observed_index=observed_index, timestamp=stamp, api=api, op=op, outcome=result, target=hashlib.sha256(str(path).encode()).hexdigest() if path else None, target_kind=kind, requested_bytes=requested, completed_bytes=completed if result == 'success' else None, repeated=integer(call.get('repeated')), file_information_class=info_class)
