"""Launch the unchanged serial workflow through an independent local Windows process broker.

Only job control changes here. Each calculation keeps its own new output
directory, existing cache mode, frozen inputs, and full acceptance gate.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'outputs/swechat_followup_20260922'


def now():
    return datetime.now(timezone.utc).isoformat()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def kernel():
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.GetCurrentProcess.restype = ctypes.c_void_p
    k.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    k.IsProcessInJob.restype = ctypes.c_int
    k.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k.OpenProcess.restype = ctypes.c_void_p
    k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    k.WaitForSingleObject.restype = ctypes.c_uint32
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    return k


def in_job(pid=None):
    k = kernel()
    handle = k.GetCurrentProcess() if pid is None else k.OpenProcess(0x400, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        answer = ctypes.c_int()
        if not k.IsProcessInJob(handle, None, ctypes.byref(answer)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(answer.value)
    finally:
        if pid is not None:
            k.CloseHandle(handle)


def alive(pid):
    k = kernel()
    handle = k.OpenProcess(0x100000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return False
        raise ctypes.WinError(error)
    try:
        return k.WaitForSingleObject(handle, 0) == 258
    finally:
        k.CloseHandle(handle)


def powershell_json(script):
    script = '[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); $ErrorActionPreference = "Stop"; ' + script
    encoded = base64.b64encode(script.encode('utf-16-le')).decode()
    result = subprocess.run(['powershell.exe', '-NoProfile', '-EncodedCommand', encoded],
                            capture_output=True, encoding='utf-8', check=True)
    return json.loads(result.stdout)


def broker_identity():
    # Check only process metadata, never command lines or unrelated sources.
    script = (f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={os.getppid()}"; '
              '$b=Get-CimInstance Win32_Process -Filter ("ProcessId="+$p.ParentProcessId); '
              '[pscustomobject]@{launcher_pid=$p.ProcessId; launcher_name=$p.Name; '
              'broker_pid=$b.ProcessId; broker_name=$b.Name} | ConvertTo-Json -Compress')
    result = powershell_json(script)
    result['verified'] = str(result.get('broker_name', '')).lower() == 'wmiprvse.exe'
    return result


def detach(args, directory):
    # WMI creates a local process through its provider, outside the tool's
    # process tree. No scheduled task, service, OS setting or remote write.
    command = subprocess.list2cmdline([sys.executable, '-u', str(Path(__file__).resolve()), *args])
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    script = ('$startup=New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly '
              '-Property @{ShowWindow=[uint16]0}; '
              '$result=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments '
              '@{CommandLine=' + quote(command) + ';CurrentDirectory=' + quote(ROOT) +
              ';ProcessStartupInformation=$startup}; '
              '$result | Select-Object ReturnValue,ProcessId | ConvertTo-Json -Compress')
    result = powershell_json(script)
    if result['ReturnValue'] != 0:
        raise RuntimeError('Local WMI process creation failed: ' + str(result))
    write(directory / 'launch.json', dict(created_at=now(), caller_pid=os.getpid(),
        launched_pid=result['ProcessId'], caller_in_job=in_job(), method='local_Win32_Process_Create',
        python=sys.executable, script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    print(json.dumps(dict(directory=str(directory), launched_pid=result['ProcessId'])), flush=True)


def run_pipeline(directory):
    config = json.loads((directory / 'configuration.json').read_text(encoding='utf-8'))
    broker = broker_identity()
    write(directory / 'identity.json', dict(pid=os.getpid(), parent_pid=os.getppid(),
          in_windows_job=in_job(), broker=broker, started_at=now()))
    if not broker['verified']:
        raise RuntimeError('Local independent process broker identity not verified')
    steps = []
    for repo, attempt in [('entireio/cli', config['entireio_attempt']),
                          ('marin-community/marin', config['marin_attempt'])]:
        steps.append((repo, ['run_swechat_additional_attempt.py', '--repository', repo,
            '--output-root', str(OUT / 'additional-attempts' / attempt),
            '--minimum-free-gib', '8', '--python-file-cache', 'accessed-imports']))
    steps.append(('full_acceptance_then_local_stage3', ['finish_swechat_verified_main.py',
        '--marin-attempt', config['marin_attempt'], '--entireio-attempt', config['entireio_attempt'],
        '--execution-name', config['execution_name']]))
    try:
        for name, arguments in steps:
            write(directory / 'progress.json', dict(stage=name, status='running', updated_at=now()))
            subprocess.run([sys.executable, '-u', str(ROOT / 'scripts' / arguments[0]), *arguments[1:]],
                           cwd=ROOT, stdout=sys.stdout, stderr=sys.stderr, check=True)
        write(directory / 'progress.json', dict(status='local_stage3_complete_external_collection_pending',
              updated_at=now()))
    except BaseException:
        import traceback
        write(directory / 'progress.json', dict(status='failed', updated_at=now(), error=traceback.format_exc()))
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['probe', 'probe-child', 'start', 'run-child'])
    parser.add_argument('--name', default='detached-process-probe-broker-20260923')
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--parent-pid', type=int)
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('Run with the project research Windows Python')
    if args.mode in {'probe-child', 'run-child'}:
        sys.stdout = (args.directory / 'stdout.txt').open('x', encoding='utf-8', buffering=1)
        sys.stderr = (args.directory / 'stderr.txt').open('x', encoding='utf-8', buffering=1)
    if args.mode == 'probe-child':
        for _ in range(100):
            if not alive(args.parent_pid):
                break
            time.sleep(0.1)
        parent_alive = alive(args.parent_pid)
        job = in_job()
        broker = broker_identity()
        write(args.directory / 'validation.json', dict(status='PASS' if not parent_alive and broker['verified'] else 'FAIL',
            observed_at=now(), actual_pid=os.getpid(), caller_pid=args.parent_pid,
            caller_still_alive=parent_alive, in_windows_job=job, broker=broker,
            scope='Survives caller exit in a verified local WMI provider process tree. No guarantee against OS reboot or explicit termination'))
        return
    if args.mode == 'run-child':
        run_pipeline(args.directory)
        return
    if Path(args.name).name != args.name:
        raise ValueError('Run name must be a basename')
    if args.mode == 'probe':
        directory = OUT / 'verification' / args.name
        directory.mkdir(exist_ok=False)
        detach(['probe-child', '--directory', str(directory), '--parent-pid', str(os.getpid())], directory)
        return
    probe = OUT / 'verification/detached-process-probe-broker-20260923/validation.json'
    if json.loads(probe.read_text(encoding='utf-8'))['status'] != 'PASS':
        raise RuntimeError('Detached launch probe must pass first')
    directory = OUT / args.name
    directory.mkdir(exist_ok=False)
    config = dict(entireio_attempt='entireio-detached-shared-gap-20260923',
        marin_attempt='marin-detached-shared-gap-20260923',
        execution_name='verified_main_execution_detached_shared_gap',
        analysis_changes=False, original_files_preserved=True,
        probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest())
    for name in (config['entireio_attempt'], config['marin_attempt']):
        if (OUT / 'additional-attempts' / name).exists():
            raise FileExistsError(name)
    if (OUT / config['execution_name']).exists():
        raise FileExistsError(config['execution_name'])
    write(directory / 'configuration.json', config)
    detach(['run-child', '--directory', str(directory)], directory)


if __name__ == '__main__':
    main()
