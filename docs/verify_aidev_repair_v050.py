#!/usr/bin/env python3
"""v050 defaults; reuse the v049 metadata verifier without changing its evidence."""
from pathlib import Path
import argparse
from verify_aidev_repair_v049 import verify, self_test

BASE = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--runs-confirmed-terminal', action='store_true')
    p.add_argument('--self-test', action='store_true')
    p.add_argument('--run', type=Path, default=BASE/'repair-runs/aidev-v050')
    p.add_argument('--report', type=Path, default=BASE/'docs/aidev_repair_v050_verification.json')
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.runs_confirmed_terminal:
        raise SystemExit(verify(a.run.resolve(), a.report.resolve()))
    else:
        p.error('--runs-confirmed-terminal is required before reading real outputs')
