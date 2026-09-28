"""Convenience launcher for the core project at this directory."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def environment() -> dict[str, str]:
    env = os.environ.copy()
    paths = [str(ROOT / 'src'), str(ROOT / 'scripts'), str(ROOT)]
    if env.get('PYTHONPATH'):
        paths.append(env['PYTHONPATH'])
    env['PYTHONPATH'] = os.pathsep.join(paths)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AgentLog 项目统一入口；不自动重跑任何研究。')
    parser.add_argument('command', nargs='?', choices=['paths', 'check', 'tool', 'research'])
    parser.add_argument('args', nargs=argparse.REMAINDER, help='原 CLI 参数，或研究脚本的相对路径及参数')
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == 'paths':
        print(json.dumps({'root': str(ROOT), 'project': str(ROOT),
                          'source': str(ROOT / 'src'), 'outputs': str(ROOT / 'outputs'),
                          'archive': str(ROOT / 'archive'), 'python': sys.executable},
                         ensure_ascii=False, indent=2))
        return 0
    if args.command == 'check':
        required = ['pyproject.toml', 'src/agentlog_unified/cli.py', 'config.example.yaml',
                    'requirements.lock', 'requirements-aidev.lock', 'configs', 'schemas',
                    'tests', 'scripts', 'data/cache', 'data/inputs', 'outputs/runs',
                    'outputs/presentations', 'papers', 'research', 'archive']
        missing = [name for name in required if not (ROOT / name).exists()]
        linked = [name for name in required if (ROOT / name).is_symlink()]
        print(json.dumps({'layout_ok': not missing and not linked, 'missing': missing,
                          'unexpected_links': linked,
                          'scope': 'directory structure only; no research or runtime validation'},
                         ensure_ascii=False, indent=2))
        return 1 if missing or linked else 0
    if sys.version_info < (3, 11):
        parser.error('运行工具或研究脚本需要 Python 3.11+；paths/check 可使用当前解释器。')
    if args.command == 'tool':
        cmd = [sys.executable, '-c', 'from agentlog_unified.cli import main; raise SystemExit(main())', *args.args]
        cwd = ROOT
    else:
        if not args.args:
            parser.error('research 后需要脚本路径，例如 scripts/agent_log_motivation_v12.py --help')
        script = (ROOT / args.args[0]).resolve()
        if not script.is_relative_to(ROOT.resolve()) or script.suffix != '.py' or not script.is_file():
            parser.error('研究脚本必须是项目内已有的 .py 文件。')
        cmd = [sys.executable, str(script), *args.args[1:]]
        cwd = ROOT
    try:
        return subprocess.run(cmd, cwd=cwd, env=environment()).returncode
    except OSError as exc:
        print(f'启动失败：{exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
