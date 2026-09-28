"""Reversible memory-priority tuning; no worker termination or suspension.

Windows may page out cold data while retaining all committed process memory and
continuing execution. No swap/pagefile configuration or source file is changed.
"""
import ctypes,json,argparse
from ctypes import wintypes as w
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'outputs/swechat_followup_20260922'
TARGETS={12156:1790085105789,24004:1790085483217}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--restore',action='store_true');args=ap.parse_args()
    k=ctypes.WinDLL('kernel32',use_last_error=True);ps=ctypes.WinDLL('psapi',use_last_error=True)
    k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
    k.CloseHandle.argtypes=[w.HANDLE]
    k.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)];k.GetProcessTimes.restype=w.BOOL
    k.GetProcessInformation.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD];k.GetProcessInformation.restype=w.BOOL
    k.SetProcessInformation.argtypes=k.GetProcessInformation.argtypes;k.SetProcessInformation.restype=w.BOOL
    ps.EmptyWorkingSet.argtypes=[w.HANDLE];ps.EmptyWorkingSet.restype=w.BOOL
    class MemoryPriority(ctypes.Structure):_fields_=[('MemoryPriority',w.ULONG)]
    before_path=OUT/'verification/duplicate_memory_priority_before.json'
    handles={};before={};actions=[]
    try:
        saved=json.loads(before_path.read_text()) if args.restore else None
        if not args.restore and before_path.exists():raise FileExistsError(before_path)
        for pid,created in TARGETS.items():
            handle=k.OpenProcess(0x0400|0x0200|0x0100,False,pid)
            if not handle:raise ctypes.WinError(ctypes.get_last_error())
            handles[pid]=handle
            times=[w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(handle,*[ctypes.byref(t) for t in times]):raise ctypes.WinError(ctypes.get_last_error())
            actual=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)//10000-11644473600000
            if actual!=created:raise RuntimeError('PID creation time changed')
            value=MemoryPriority()
            if not k.GetProcessInformation(handle,0,ctypes.byref(value),ctypes.sizeof(value)):raise ctypes.WinError(ctypes.get_last_error())
            before[str(pid)]=dict(creation_unix_ms=created,memory_priority=value.MemoryPriority)
        if not args.restore:
            with before_path.open('x',encoding='utf-8') as f:json.dump(before,f,indent=2)
        for pid,handle in handles.items():
            value=MemoryPriority(saved[str(pid)]['memory_priority'] if args.restore else 1)
            if not k.SetProcessInformation(handle,0,ctypes.byref(value),ctypes.sizeof(value)):raise ctypes.WinError(ctypes.get_last_error())
            trimmed=None if args.restore else bool(ps.EmptyWorkingSet(handle))
            actions.append(dict(pid=pid,memory_priority=value.MemoryPriority,working_set_trimmed=trimmed))
        report=dict(time=datetime.now(timezone.utc).isoformat(),restore=args.restore,actions=actions,
                    workers_terminated=False,workers_suspended=False,progress_discarded=False,
                    files_deleted=False,system_pagefile_configuration_changed=False,
                    documentation=['https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation',
                                   'https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-emptyworkingset'])
        dest=OUT/'verification'/('duplicate_memory_priority_restored.json' if args.restore else 'duplicate_memory_priority_reduced.json')
        with dest.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
        print(json.dumps(report))
    finally:
        for handle in handles.values():k.CloseHandle(handle)

if __name__=='__main__':main()
