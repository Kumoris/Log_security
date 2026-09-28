"""Pause/resume identified duplicate worker threads without losing their state.

No termination, source-file writes, debugger injection or pagefile changes.
The resume receipt is written before pausing and the rollback resumes any thread
already paused by this operation if an error occurs.
"""
import ctypes,json,argparse
from ctypes import wintypes as w
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'outputs/swechat_followup_20260922'
TARGETS={12156:1790085105789,24004:1790085483217}

class APIs:
    def __init__(self):
        self.k=ctypes.WinDLL('kernel32',use_last_error=True);self.ps=ctypes.WinDLL('psapi',use_last_error=True)
        k=self.k
        k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
        k.OpenThread.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenThread.restype=w.HANDLE
        k.CloseHandle.argtypes=[w.HANDLE]
        k.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)];k.GetProcessTimes.restype=w.BOOL
        k.GetProcessIdOfThread.argtypes=[w.HANDLE];k.GetProcessIdOfThread.restype=w.DWORD
        k.SuspendThread.argtypes=[w.HANDLE];k.SuspendThread.restype=w.DWORD
        k.ResumeThread.argtypes=[w.HANDLE];k.ResumeThread.restype=w.DWORD
        k.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];k.CreateToolhelp32Snapshot.restype=w.HANDLE
        class Thread(ctypes.Structure):
            _fields_=[('dwSize',w.DWORD),('cntUsage',w.DWORD),('th32ThreadID',w.DWORD),('th32OwnerProcessID',w.DWORD),('tpBasePri',w.LONG),('tpDeltaPri',w.LONG),('dwFlags',w.DWORD)]
        self.Thread=Thread
        for name in ['Thread32First','Thread32Next']:
            fn=getattr(k,name);fn.argtypes=[w.HANDLE,ctypes.POINTER(Thread)];fn.restype=w.BOOL
        self.ps.EmptyWorkingSet.argtypes=[w.HANDLE];self.ps.EmptyWorkingSet.restype=w.BOOL
    def process(self,pid,expected):
        handle=self.k.OpenProcess(0x0400|0x0100,False,pid)
        if not handle:raise ctypes.WinError(ctypes.get_last_error())
        times=[w.FILETIME() for _ in range(4)]
        if not self.k.GetProcessTimes(handle,*[ctypes.byref(t) for t in times]):
            self.k.CloseHandle(handle);raise ctypes.WinError(ctypes.get_last_error())
        actual=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)//10000-11644473600000
        if expected is not None and actual!=expected:
            self.k.CloseHandle(handle);raise RuntimeError('PID reused; no action')
        return handle,actual
    def threads(self,pids):
        snapshot=self.k.CreateToolhelp32Snapshot(4,0)
        if snapshot==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        result=[]
        try:
            row=self.Thread();row.dwSize=ctypes.sizeof(row)
            ok=self.k.Thread32First(snapshot,ctypes.byref(row))
            while ok:
                if row.th32OwnerProcessID in pids:result.append(dict(pid=row.th32OwnerProcessID,tid=row.th32ThreadID))
                ok=self.k.Thread32Next(snapshot,ctypes.byref(row))
        finally:self.k.CloseHandle(snapshot)
        return result
    def thread(self,row):
        handle=self.k.OpenThread(0x0800|0x0002,False,row['tid'])
        if not handle:raise ctypes.WinError(ctypes.get_last_error())
        if self.k.GetProcessIdOfThread(handle)!=row['pid']:
            self.k.CloseHandle(handle);raise RuntimeError('Thread changed owner')
        return handle

def pause(targets,receipt):
    api=APIs();processes={};threads=[];paused=[]
    if receipt.exists():raise FileExistsError(receipt)
    try:
        for pid,created in targets.items():processes[pid]=api.process(pid,created)[0]
        rows=api.threads(set(targets))
        if {r['pid'] for r in rows}!=set(targets):raise RuntimeError('Missing worker threads')
        for row in rows:threads.append((row,api.thread(row)))
        record=dict(created_at=datetime.now(timezone.utc).isoformat(),targets=targets,threads=rows,status='planned',termination=False,files_deleted=False)
        receipt.write_text(json.dumps(record,indent=2))
        for row,handle in threads:
            prior=api.k.SuspendThread(handle)
            if prior==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
            if prior!=0:
                api.k.ResumeThread(handle);raise RuntimeError('Thread already suspended by another actor')
            paused.append(handle)
        if api.threads(set(targets))!=rows:raise RuntimeError('Thread set changed during pause')
        record.update(status='paused_state_retained',working_set_trimmed={pid:bool(api.ps.EmptyWorkingSet(h)) for pid,h in processes.items()})
        receipt.write_text(json.dumps(record,indent=2))
        print(json.dumps(dict(status=record['status'],pids=list(targets),threads=len(rows),termination=False)))
    except BaseException:
        for handle in reversed(paused):api.k.ResumeThread(handle)
        if receipt.exists():
            record=json.loads(receipt.read_text());record['status']='rolled_back';receipt.write_text(json.dumps(record,indent=2))
        raise
    finally:
        for _,handle in threads:api.k.CloseHandle(handle)
        for handle in processes.values():api.k.CloseHandle(handle)

def resume(receipt):
    record=json.loads(receipt.read_text())
    if record['status']!='paused_state_retained':raise RuntimeError('Receipt is not a paused state')
    api=APIs();handles=[]
    try:
        for pid,created in record['targets'].items():handles.append(api.process(int(pid),created)[0])
        for row in record['threads']:
            handle=api.thread(row)
            try:
                prior=api.k.ResumeThread(handle)
                if prior!=1:raise RuntimeError('Unexpected suspension count; inspect before another action')
            finally:api.k.CloseHandle(handle)
        record['status']='resumed';record['resumed_at']=datetime.now(timezone.utc).isoformat();receipt.write_text(json.dumps(record,indent=2))
        print(json.dumps(dict(status='resumed',pids=list(record['targets']))))
    finally:
        for handle in handles:api.k.CloseHandle(handle)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--resume',action='store_true');args=ap.parse_args()
    receipt=OUT/'verification/duplicate_preserved_state.json'
    if args.resume:resume(receipt)
    else:pause(TARGETS,receipt)
