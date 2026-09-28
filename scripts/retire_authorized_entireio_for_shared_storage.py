"""Retire only Entireio PID 9076 after the explicit shared-storage rerun approval."""
import ctypes
import json
from ctypes import wintypes as w
from datetime import datetime, timezone
from preserve_duplicate_worker_state import APIs, OUT


def main():
    dest = OUT / 'verification/authorized_entireio_shared_storage_retirement.json'
    if dest.exists():
        raise FileExistsError(dest)
    directory = OUT / 'additional-attempts/entireio-complete-cache-8g-resume-20260922/repositories/entireio--cli'
    if int((directory / 'execution.lock').read_text()) != 9076:
        raise RuntimeError('Worker identity mismatch')
    if (directory / 'summary.json').exists():
        raise RuntimeError('Worker has completed; use its result instead of terminating')
    api = APIs()
    k = api.k
    k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    k.TerminateProcess.restype = w.BOOL
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.WaitForSingleObject.restype = w.DWORD
    h = k.OpenProcess(0x100000 | 0x0400 | 0x0001, False, 9076)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(h, *[ctypes.byref(t) for t in times]):
            raise ctypes.WinError(ctypes.get_last_error())
        actual = ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) // 10000 - 11644473600000
        if actual != 1790087332266:
            raise RuntimeError('PID reused; no action')
        receipt = dict(status='identity_verified', pid=9076, creation_unix_ms=actual,
                       authorization='User explicitly approved terminating/re-running Entireio with the validated shared gap storage; preserve every existing file and run repositories serially.',
                       other_processes_terminated=[], files_deleted=False,
                       prior_progress=json.loads((directory / 'progress.json').read_text()),
                       recorded_at=datetime.now(timezone.utc).isoformat())
        dest.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        if not k.TerminateProcess(h, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if k.WaitForSingleObject(h, 10000) != 0:
            raise RuntimeError('Termination did not finish')
        receipt['status'] = 'authorized_retirement_complete'
        dest.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(dict(status=receipt['status'], pid=9076, files_deleted=False)), flush=True)
    finally:
        k.CloseHandle(h)


if __name__ == '__main__':
    main()
