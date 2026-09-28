"""Retire only the identified recent duplicate experiment; originals keep running."""
from run_swechat_followups import *
from datetime import datetime,timezone

def main():
    import base64
    attempt=OUT/'additional-attempts/marin-evaluation-8g'
    directory=attempt/'repositories/marin-community--marin'
    original=OUT/'repositories/marin-community--marin'
    if (directory/'summary.json').exists():raise RuntimeError('Trial has completed; keep its result')
    if int((directory/'execution.lock').read_text())!=36256:raise RuntimeError('Trial identity changed')
    if int((original/'execution.lock').read_text())!=26044:raise RuntimeError('Original identity changed')
    oracle=json.loads((OUT/'verification/actual_python_file_cache_oracle.json').read_text())
    if oracle['status']!='PASS':raise RuntimeError('Replacement adapter not validated')
    if '6 passed' not in (OUT/'verification/python_file_cache_tests.txt').read_text():raise RuntimeError('Tests not passed')
    script='''$ErrorActionPreference="Stop"
$p=Get-CimInstance Win32_Process -Filter "ProcessId=36256"
$o=Get-CimInstance Win32_Process -Filter "ProcessId=26044"
$parent=Get-CimInstance Win32_Process -Filter "ProcessId=25240"
if (!$p -or !$o -or !$parent) {throw "Required original/trial identities not present"}
if (([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds() -ne 1790022373690) {throw "PID reused"}
if ($p.ParentProcessId -ne 25344 -or $p.CommandLine -notmatch "execute_swechat_followups.py.*--repository marin-community/marin") {throw "Unexpected trial"}
if (([DateTimeOffset]$o.CreationDate).ToUnixTimeMilliseconds() -ne 1790016915568 -or $o.CommandLine -notmatch "execute_swechat_followups.py.*--repository marin-community/marin") {throw "Original no longer identified"}
if ($parent.CommandLine -notmatch "marin-evaluation-8g") {throw "Unexpected trial coordinator"}
Stop-Process -Id 36256 -ErrorAction Stop
[pscustomobject]@{stoppedDuplicateTrial=36256;originalStillPresent=[bool](Get-Process -Id 26044 -ErrorAction SilentlyContinue)}|ConvertTo-Json
'''
    q=subprocess.run(['powershell.exe','-NoProfile','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],capture_output=True)
    result=dict(timestamp=datetime.now(timezone.utc).isoformat(),trial=str(attempt),trial_progress=json.loads((directory/'progress.json').read_text()),
                purpose='Replace only recent duplicate trial after validated file-cache improvement; retain original miner and every existing output',
                returncode=q.returncode,stdout=q.stdout.decode(errors='replace'),stderr=q.stderr.decode(errors='replace'))
    dump(OUT/'verification/duplicate_trial_retirement.json',result)
    if q.returncode:raise RuntimeError(result['stderr'])
    print(result['stdout'])

if __name__=='__main__':main()
