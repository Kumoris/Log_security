"""Terminate only Marin PID 31780 under the user's explicit authorization."""
import ctypes
import json
from ctypes import wintypes as w
from datetime import datetime, timezone
from preserve_duplicate_worker_state import APIs, OUT


def main():
    dest = OUT / 'verification/authorized_marin_serial_retirement.json'
    if dest.exists():
        raise FileExistsError(dest)
    directory = OUT / 'additional-attempts/marin-accessed-import-active-20260922/repositories/marin-community--marin'
    if int((directory / 'execution.lock').read_text()) != 31780:
        raise RuntimeError('Main worker PID mismatch')
    api = APIs()
    k = api.k
    k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    k.TerminateProcess.restype = w.BOOL
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.WaitForSingleObject.restype = w.DWORD
    h = k.OpenProcess(0x100000 | 0x0400 | 0x0001, False, 31780)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(h, *[ctypes.byref(t) for t in times]):
            raise ctypes.WinError(ctypes.get_last_error())
        actual = ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) // 10000 - 11644473600000
        if actual != 1790088946801:
            raise RuntimeError('PID reused; no action')
        receipt = dict(status='identity_verified', pid=31780, creation_unix_ms=actual,
                       authorization='User explicitly approved terminating Marin 31780 and rerunning it serially after Entireio; preserve every existing file.',
                       other_processes_terminated=[], kept_entireio_pid=9076,
                       discarded_unpersisted_snapshots=850, files_deleted=False,
                       prior_marin_progress=json.loads((directory / 'progress.json').read_text()),
                       recorded_at=datetime.now(timezone.utc).isoformat())
        dest.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        if not k.TerminateProcess(h, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if k.WaitForSingleObject(h, 10000) != 0:
            raise RuntimeError('Termination did not finish')
        receipt['status'] = 'authorized_retirement_complete'
        dest.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(dict(status=receipt['status'], pid=31780, files_deleted=False)), flush=True)
    finally:
        k.CloseHandle(h)


if __name__ == '__main__':
    main()
