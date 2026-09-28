"""Resource scheduling only: resume the same Marin process after Entireio exits."""
import json,time,ctypes
from datetime import datetime,timezone
from preserve_duplicate_worker_state import OUT,resume

class Memory(ctypes.Structure):
    _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in
        ['total','available','page_total','page_available','virtual_total','virtual_available','extended']]

def main():
    receipt=OUT/'verification/marin_serial_memory_schedule.json'
    log=OUT/'verification/marin_serial_resume_progress.json'
    if log.exists():raise FileExistsError(log)
    while True:
        saved=json.loads(receipt.read_text(encoding='utf-8'))
        if saved['status']!='paused_state_retained':
            raise RuntimeError('Expected a paused, preserved process')
        upstream=json.loads((OUT/'additional-attempts/entireio-complete-cache-8g-resume-20260922/attempt_status.json').read_text(encoding='utf-8'))
        m=Memory();m.length=ctypes.sizeof(m)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):raise RuntimeError('Memory unavailable')
        available=min(m.available,m.page_available)/1024**3
        done=upstream['status'] in {'finished','execution_failed'}
        report=dict(stage='waiting_for_entireio_exit_and_memory',upstream_status=upstream['status'],
                    available_physical_gib=round(m.available/1024**3,2),available_commit_gib=round(m.page_available/1024**3,2),
                    required_free_gib=6,updated_at=datetime.now(timezone.utc).isoformat())
        log.write_text(json.dumps(report,indent=2),encoding='utf-8')
        if done and available>=6:
            resume(receipt)  # verifies exact PID creation time and original thread ownership
            report.update(stage='same_marin_process_resumed',pid=31780,restarted=False)
            log.write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps(report),flush=True)
            return
        time.sleep(30)

if __name__=='__main__':main()
