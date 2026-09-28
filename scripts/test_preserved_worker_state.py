"""Only a disposable synthetic counter process; no dataset or worker is touched."""
import subprocess,sys,time,json
from pathlib import Path
import pytest
from preserve_duplicate_worker_state import APIs,pause,resume

@pytest.mark.skipif(sys.platform!='win32',reason='Windows process-control test')
def test_counter_resumes_from_preserved_memory(tmp_path):
    counter=tmp_path/'counter.txt';receipt=tmp_path/'state.json'
    code='import sys,time,os\nfrom pathlib import Path\np=Path(sys.argv[1]); n=0\nwhile True:\n n+=1\n q=p.with_suffix(".temporary");q.write_text(str(n));os.replace(q,p);time.sleep(.03)\n'
    child=subprocess.Popen([sys._base_executable,'-c',code,str(counter)])
    try:
        for _ in range(100):
            if counter.exists():break
            time.sleep(.03)
        assert counter.exists()
        api=APIs();h,created=api.process(child.pid,None);api.k.CloseHandle(h)
        pause({child.pid:created},receipt)
        frozen=int(counter.read_text());time.sleep(.2)
        assert child.poll() is None and int(counter.read_text())==frozen
        resume(receipt);time.sleep(.2)
        assert child.poll() is None and int(counter.read_text())>frozen
        assert json.loads(receipt.read_text())['status']=='resumed'
    finally:
        if child.poll() is None:
            if receipt.exists() and json.loads(receipt.read_text())['status']=='paused_state_retained':resume(receipt)
            child.terminate();child.wait(timeout=5)
