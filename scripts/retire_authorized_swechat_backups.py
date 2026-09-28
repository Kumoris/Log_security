"""Retire the two additional duplicate groups explicitly authorized by the user."""
import ctypes,json
from ctypes import wintypes as w
from datetime import datetime,timezone
from preserve_duplicate_worker_state import APIs,OUT

TARGETS={11796:(1790087935809,'marin-full-validated-cache-20260922','marin-community--marin'),
         31716:(1790088869533,'entireio-validated-resume-20260922','entireio--cli')}

def main():
    dest=OUT/'verification/authorized_backup_workers_retirement.json'
    if dest.exists():raise FileExistsError(dest)
    api=APIs();k=api.k;handles={};verified=[]
    k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];k.TerminateProcess.restype=w.BOOL
    k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
    try:
        for pid,(created,attempt,repo) in TARGETS.items():
            directory=OUT/'additional-attempts'/attempt/'repositories'/repo
            if int((directory/'execution.lock').read_text())!=pid:raise RuntimeError('Run PID mismatch')
            h=k.OpenProcess(0x100000|0x0400|0x0001,False,pid)
            if not h:raise ctypes.WinError(ctypes.get_last_error())
            handles[pid]=h;times=[w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(h,*[ctypes.byref(t) for t in times]):raise ctypes.WinError(ctypes.get_last_error())
            actual=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)//10000-11644473600000
            if actual!=created:raise RuntimeError('PID reused')
            verified.append(dict(pid=pid,creation_unix_ms=actual,directory=str(directory)))
        receipt=dict(status='identity_verified',targets=verified,terminated=[],files_deleted=False,
                     kept_active_workers=[31780,9076],created_at=datetime.now(timezone.utc).isoformat(),
                     authorization='User explicitly allowed termination of 11796 and the duplicate group 31716/93971; keep all files and active workers 31780/9076.')
        dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        for pid,h in handles.items():
            if not k.TerminateProcess(h,1):raise ctypes.WinError(ctypes.get_last_error())
            if k.WaitForSingleObject(h,10000)!=0:raise RuntimeError('Termination timeout')
            receipt['terminated'].append(pid)
            dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        receipt['status']='authorized_termination_complete'
        dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        print(json.dumps(dict(status=receipt['status'],terminated=receipt['terminated'],files_deleted=False)))
    finally:
        for h in handles.values():k.CloseHandle(h)

if __name__=='__main__':main()
