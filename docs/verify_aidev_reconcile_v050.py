#!/usr/bin/env python3
"""v050 defaults; reuse the v049 metadata verifier without changing its evidence."""
from pathlib import Path
import argparse
from verify_aidev_reconcile_v049 import verify, self_test

BASE = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--runs-confirmed-terminal', action='store_true')
    p.add_argument('--self-test', action='store_true')
    p.add_argument('--run', type=Path, default=BASE/'reconciled-runs/aidev-v050')
    p.add_argument('--report', type=Path, default=BASE/'docs/aidev_reconcile_v050_verification.json')
    p.add_argument('--execution', type=Path)
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.runs_confirmed_terminal:
        raise SystemExit(verify(a.run.resolve(), a.report.resolve(), a.execution.resolve() if a.execution else None))
    else:
        p.error('--runs-confirmed-terminal is required before reading real outputs')
