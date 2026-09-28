"""Read-only progress monitor; never launches or stops research workers."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import os
import sys
from zoneinfo import ZoneInfo
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1] / 'outputs/swechat_followup_20260922'


def read(path):
    for attempt in range(3):
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            if attempt == 2:
                raise
            time.sleep(0.05)


def sample():
    pipeline = ROOT / 'detached_serial_shared_gap_20260923'
    state = read(pipeline / 'progress.json')
    ids = [read(pipeline / 'identity.json')['pid']]
    result = dict(time=datetime.now(timezone.utc).isoformat(),
                  pipeline_status=state['status'], pipeline_stage=state.get('stage'))
    for short, name in [('entireio', 'entireio-detached-shared-gap-20260923'),
                        ('marin', 'marin-detached-shared-gap-20260923')]:
        directory = ROOT / 'additional-attempts' / name
        status = read(directory / 'attempt_status.json')['status'] if (directory / 'attempt_status.json').exists() else 'not_started'
        progress = [read(p) for p in directory.glob('repositories/*/progress.json')]
        result[short] = dict(status=status)
        if progress:
            result[short].update({k: v for k, v in progress[0].items()
                                 if k not in {'repository', 'guard_unique_sources'}})
        if status == 'running':
            ids.extend(int(p.read_text()) for p in directory.glob('repositories/*/execution.lock'))
    script = ('[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); '
              '@(Get-Process -Id ' + ','.join(str(int(pid)) for pid in ids) +
              ' -ErrorAction SilentlyContinue | Select-Object Id,CPU,PrivateMemorySize64) | ConvertTo-Json -Compress')
    try:
        q = subprocess.run(['/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
                            '-NoProfile', '-EncodedCommand',
                            base64.b64encode(script.encode('utf-16-le')).decode()],
                           capture_output=True, text=True, timeout=15)
        processes = json.loads(q.stdout) if q.stdout.strip() else []
        if isinstance(processes, dict):
            processes = [processes]
        result['live'] = [dict(pid=p['Id'], cpu_seconds=p.get('CPU'),
                               private_gib=round(p['PrivateMemorySize64']/1024**3, 2)) for p in processes]
        result['process_query_returncode'] = q.returncode
    except (subprocess.TimeoutExpired, ValueError) as exc:
        result['process_query_error'] = type(exc).__name__
    return result


LABELS = {
    'running': '运行中', 'detecting': '快照检测', 'tracing': '日志追踪',
    'detected': '快照检测完成，等待追踪结果',
    'complete': '已完成', 'executed': '已完成', 'finished': '已完成',
    'failed': '失败', 'execution_failed': '执行失败', 'start': '启动',
    'mined': '历史采集完成', 'not_started': '尚未启动',
    'waiting_for_memory': '等待可用内存',
    'full_acceptance_then_local_stage3': '验收与本地第三步',
    'local_stage3_complete_external_collection_pending': '本地完成，外部证据待收集',
}


def label(value):
    return LABELS.get(value, value or '暂无数据')


def beijing_time(value):
    if not value:
        return '暂无数据'
    try:
        return datetime.fromisoformat(value).astimezone(ZoneInfo('Asia/Shanghai')).strftime('%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(value)


def duration(seconds):
    if seconds is None:
        return '暂无数据'
    seconds = max(0, int(seconds))
    return f'{seconds // 3600} 小时 {seconds % 3600 // 60:02d} 分'


def render(value, previous=None, *, interval=30, expected_snapshots=None):
    lines = ['━' * 56, '  Agent 日志研究 · 实时运行状态', '━' * 56]
    if 'monitor_error' in value:
        lines.extend(['  监控读取失败：' + value['monitor_error'],
                      '  详情：' + str(value.get('detail', '')), '',
                      '  此错误不代表后台计算已停止。'])
        return '\n'.join(lines)
    lines.extend([
        f"  采样时间  {beijing_time(value.get('time'))}（北京时间）",
        f"  整体状态  {label(value.get('pipeline_status'))}",
        f"  当前任务  {label(value.get('pipeline_stage'))}", '',
    ])
    for key, name in [('entireio', 'entireio/cli'), ('marin', 'marin-community/marin')]:
        state = value.get(key, {})
        lines.append(f"  {name}  ·  {label(state.get('stage') or state.get('status'))}")
        count = state.get('snapshots')
        if count is not None:
            before = (previous or {}).get(key, {}).get('snapshots')
            change = f'  |  较上次 +{count - before:,}' if before is not None and count >= before else ''
            lines.append(f'    快照读取  {count:,} 次{change}')
            if key == 'marin' and expected_snapshots:
                ratio = count / expected_snapshots
                filled = min(24, max(0, int(ratio * 24)))
                bar = '█' * filled + '░' * (24 - filled)
                lines.append(f'    [{bar}]  {ratio:.1%}（估计总量 {expected_snapshots:,}）')
        if state.get('stage') == 'detected':
            lines.append('    快照阶段已结束；追踪结果与最终验收尚未回报。')
        if state.get('elapsed_seconds') is not None:
            lines.append('    仓库已运行  ' + duration(state['elapsed_seconds']))
        if state.get('stage') == 'tracing':
            lines.append(f"    提交上下文  {state.get('contexts_considered', '?')} / {state.get('total_contexts', '?')}  |  后续记录 {state.get('followup_rows', '?')}")
        if state.get('stage') == 'complete':
            lines.append(f"    候选 {state.get('candidates', '?')}  |  发生后续修改 {state.get('initial_logs_with_changes', '?')}")
        if state.get('time'):
            lines.append('    进度更新时间  ' + beijing_time(state['time']))
        lines.append('')
    lines.append('  进程活动')
    old = {p['pid']: p for p in (previous or {}).get('live', [])}
    for process in value.get('live', []):
        pid, cpu = process['pid'], process.get('cpu_seconds')
        prior_cpu = old.get(pid, {}).get('cpu_seconds')
        activity = '首次采样'
        if cpu is not None and prior_cpu is not None:
            delta = cpu - prior_cpu
            activity = f'CPU +{delta:.1f} 秒' if delta >= 0 else 'CPU 计数重置'
        total = f'{cpu:,.1f} 秒' if cpu is not None else '未知'
        lines.append(f"    PID {pid:<6}  内存 {process['private_gib']:.2f} GiB  |  {activity}")
        lines.append(f'                CPU 累计 {total}')
    if value.get('process_query_error') or value.get('process_query_returncode', 0) != 0:
        lines.append('    进程查询失败；无法据此判断后台是否仍在运行。')
    elif value.get('live') == []:
        lines.append('    未查到监控目标进程，请结合整体状态检查。')
    lines.extend(['', '─' * 56,
                  f'  每 {interval:g} 秒采样 · 快照数每 5 次更新',
                  '  进度条仅代表快照阶段，100% 不代表全流程验收完成。',
                  '  CPU 增量是计算用时；本面板不把短暂停顿判为卡死。',
                  '  Ctrl+C 退出监控，后台计算继续运行。'])
    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--samples', type=int, default=360)
    ap.add_argument('--interval', type=float, default=45)
    ap.add_argument('--format', choices=['pretty', 'json'], default='pretty',
                    help='pretty: readable live panel (default); json: original machine-readable rows')
    ap.add_argument('--no-clear', action='store_true', help='append panels instead of refreshing in place')
    ap.add_argument('--expected-snapshots', type=int,
                    help='optional estimated total for Marin; display only, not a completion criterion')
    args = ap.parse_args()
    if not 1 <= args.interval <= 45:
        ap.error('Interval must be between 1 and 45 seconds')
    if args.samples < 1:
        ap.error('Samples must be positive')
    if args.expected_snapshots is not None and args.expected_snapshots < 1:
        ap.error('Expected snapshots must be positive')
    redraw = args.format == 'pretty' and sys.stdout.isatty() and os.environ.get('TERM') != 'dumb' and not args.no_clear
    previous = None
    try:
        for index in range(args.samples):
            try:
                value = sample()
            except (OSError, ValueError) as exc:
                value = dict(monitor_error=type(exc).__name__, detail=str(exc))
            if args.format == 'json':
                print(json.dumps(value, ensure_ascii=False), flush=True)
            else:
                print(('\033[2J\033[H' if redraw else '') + render(value, previous,
                      interval=args.interval, expected_snapshots=args.expected_snapshots), flush=True)
            if ('monitor_error' in value or value.get('pipeline_status') != 'running'
                    or (value.get('live') == [] and value.get('process_query_returncode') == 0)
                    or any(value.get(k, {}).get('status') == 'execution_failed'
                           for k in ('entireio', 'marin'))):
                break
            previous = value
            if index + 1 < args.samples:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        if args.format == 'pretty':
            print('\n已退出监控；后台计算不受影响。', flush=True)


if __name__ == '__main__':
    main()
