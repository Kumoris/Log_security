"""Retire only the three comparison PIDs explicitly authorized by the user."""
import ctypes
import json
from ctypes import wintypes as w
from pathlib import Path
from datetime import datetime, timezone
from preserve_duplicate_worker_state import APIs, OUT

TARGETS = {
    12156: (1790085105789, 'marin-validated-resume-20260922'),
    24004: (1790085483217, 'marin-resolved-import-resume-20260922'),
    15292: (1790085957770, 'marin-complete-cache-resume-20260922'),
}


def main():
    dest=OUT/'verification/authorized_comparisons_retirement.json'
    if dest.exists():raise FileExistsError(dest)
    api=APIs();k=api.k;handles={};verified=[]
    k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];k.TerminateProcess.restype=w.BOOL
    k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
    try:
        for pid,(created,attempt) in TARGETS.items():
            directory=OUT/'additional-attempts'/attempt/'repositories/marin-community--marin'
            if int((directory/'execution.lock').read_text())!=pid:raise RuntimeError('Run PID mismatch')
            handle=k.OpenProcess(0x100000|0x0400|0x0001,False,pid)
            if not handle:raise ctypes.WinError(ctypes.get_last_error())
            handles[pid]=handle
            times=[w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(handle,*[ctypes.byref(t) for t in times]):raise ctypes.WinError(ctypes.get_last_error())
            actual=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)//10000-11644473600000
            if actual!=created:raise RuntimeError('PID reused; no termination')
            verified.append(dict(pid=pid,creation_unix_ms=actual,attempt=str(directory.parent.parent),
                                 last_progress=json.loads((directory/'progress.json').read_text(encoding='utf-8'))))
        receipt=dict(status='identity_verified',created_at=datetime.now(timezone.utc).isoformat(),
                     authorization='User explicitly permitted termination of PIDs 12156, 24004, 15292; keep every file and main run.',
                     targets=verified,terminated=[],files_deleted=False,main_workers_modified=False)
        dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        for pid,handle in handles.items():
            if not k.TerminateProcess(handle,1):raise ctypes.WinError(ctypes.get_last_error())
            if k.WaitForSingleObject(handle,10000)!=0:raise RuntimeError('Termination did not complete')
            receipt['terminated'].append(pid)
            dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        receipt.update(status='authorized_termination_complete',finished_at=datetime.now(timezone.utc).isoformat())
        dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        print(json.dumps(dict(status=receipt['status'],terminated=receipt['terminated'],files_deleted=False)))
    finally:
        for handle in handles.values():k.CloseHandle(handle)


if __name__=='__main__':main()
