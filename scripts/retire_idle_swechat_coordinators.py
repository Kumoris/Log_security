"""Replace two idle coordinators; neither owns computed repository results."""
import ctypes,json
from ctypes import wintypes as w
from datetime import datetime,timezone
from preserve_duplicate_worker_state import APIs,OUT

def main():
    queue=OUT/'additional-attempts/marin-accessed-import-cache-20260922'
    state=json.loads((queue/'attempt_status.json').read_text(encoding='utf-8'))
    gate=json.loads((OUT/'verified_main_execution/progress.json').read_text(encoding='utf-8'))
    if state['status']!='waiting_for_earlier_attempt' or (queue/'execution.txt').exists() or (queue/'repositories').exists():
        raise RuntimeError('Queue has started computing; do not stop')
    if gate['stage']!='waiting_for_complete_stage2_repositories' or (OUT/'stage2').exists():
        raise RuntimeError('Acceptance has started; do not stop')
    if list((OUT/'verified_main_execution').glob('*.txt')):
        raise RuntimeError('Acceptance commands have already run')
    dest=OUT/'verification/idle_coordinators_replaced_after_memory_release.json'
    if dest.exists():raise FileExistsError(dest)
    targets={27988:1790088046426,18172:1790088797749}
    api=APIs();k=api.k;handles={}
    k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];k.TerminateProcess.restype=w.BOOL
    try:
        for pid,created in targets.items():
            handle=k.OpenProcess(0x0400|0x0001,False,pid)
            if not handle:raise ctypes.WinError(ctypes.get_last_error())
            handles[pid]=handle;times=[w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(handle,*[ctypes.byref(t) for t in times]):raise ctypes.WinError(ctypes.get_last_error())
            actual=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)//10000-11644473600000
            if actual!=created:raise RuntimeError('PID reused')
        receipt=dict(targets=targets,queue_precondition=state,gate_precondition=gate,
                     action='replace_idle_coordinators_only',computation_discarded=False,files_deleted=False,
                     created_at=datetime.now(timezone.utc).isoformat(),completed=[])
        dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        for pid,h in handles.items():
            if not k.TerminateProcess(h,1):raise ctypes.WinError(ctypes.get_last_error())
            receipt['completed'].append(pid)
            dest.write_text(json.dumps(receipt,indent=2),encoding='utf-8')
        print(json.dumps(dict(status='idle_coordinators_replaced',pids=receipt['completed'],files_deleted=False)))
    finally:
        for h in handles.values():k.CloseHandle(h)

if __name__=='__main__':main()
