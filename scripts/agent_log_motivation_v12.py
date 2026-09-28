"""Stage-three continuation, preserving v1.1 and all upstream selections.

Adds a portable immutable input view, exact log-blob anchors for dependency
changes, distinct failed/empty collection states, and linear-time judging.
All external collection is read-only; offline replay is the default.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path
from run_swechat_followups import resolve_path
from datetime import datetime, timezone

import agent_log_motivation_v11 as v11
from agent_log_motivation_v11 import file_hash, rows, write_json, table


class Collector(v11.Collector):
    def collect(self, event, detail):
        start = len(self.store.missing)
        super().collect(event, detail)
        endpoint = f"repos/{event['repository']}/commits/{event['modification_sha']}/pulls"
        _, failures = self.cache.get((endpoint, True), (None, []))
        if failures:
            # A failed or partially read page is not an empty successful query.
            self.store.missing[start:] = [g for g in self.store.missing[start:]
                if g['reason'] != 'no_pr_returned_for_exact_commit']


def prepare_view(trace, out, guard):
    """Copy only analysis inputs, then add guarded SHA:path blobs to the new view."""
    from run_swechat_followups import git
    trace, view = Path(trace), Path(out) / 'trace_view'
    data = trace / 'data' if (trace / 'data/followups.jsonl').exists() else trace
    view.mkdir()
    hashes = {}
    for name in ('repositories', 'commits', 'file_changes', 'log_changes', 'followups', 'candidate_ledger', 'upstream_event_map'):
        p = data / (name + '.jsonl')
        if p.exists():
            hashes[str(p.resolve())] = file_hash(p)
            shutil.copyfile(p, view / p.name)
    repos = {r['id']: r for _, r in rows(view / 'repositories.jsonl')}
    keys = set()
    for _, e in rows(view / 'followups.jsonl'):
        for side, sha in (('before', e.get('parent_sha')), ('after', e.get('sha'))):
            entity = e.get(side)
            if entity and sha:
                keys.add((e['repository_id'], sha, entity['path']))
    anchors, gaps = [], []
    existing = {(a['repository_id'], a['sha'], a['path']): a for _, a in rows(data / 'log_source_anchors.jsonl')}
    for number, key in enumerate(sorted(keys), 1):
        rid, sha, path = key
        repo = repos[rid]
        # Check path before loading a blob. Structural guard checks follow before
        # any source enters the development view or is displayed.
        status = 'guard_protected' if not guard.check_path(repo['repository'], path) else None
        source = None
        if status is None:
            local = resolve_path(repo['local_repo_path'])
            source = git(local, ['show', sha + ':' + path])
            if source is None and key in existing:
                source = existing[key].get('source')
            status = guard.check(repo['repository'], path, source) if source is not None else 'git_blob_unavailable'
        if status == 'allowed':
            raw = source.encode('utf-8')
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            real = git(resolve_path(repo['local_repo_path']), ['rev-parse', sha + ':' + path])
            real = real.strip() if real else (existing.get(key) or {}).get('git_blob_id')
            if real == blob:
                anchors.append(dict(repository_id=rid, sha=sha, path=path, source=source,
                    source_sha256=v11.digest(source), git_blob_id=blob,
                    source_locator=str(repo['local_repo_path']) + ' :: ' + sha + ':' + path))
            else:
                status = 'git_blob_hash_mismatch'
        if status != 'allowed':
            gaps.append({'anchor_key_sha256': v11.digest(key), 'reason': status})
        if number % 100 == 0 or number == len(keys):
            write_json(Path(out) / 'progress.json', {'stage': 'guarded_log_blob_anchors', 'processed': number, 'total': len(keys)})
    with (view / 'log_source_anchors.jsonl').open('x', encoding='utf-8') as f:
        for a in anchors:
            f.write(v11.canonical(a) + '\n')
    write_json(Path(out) / 'anchor_validation.json', {'requested': len(keys), 'validated': len(anchors), 'gaps': gaps, 'guard_calls': dict(guard.calls)})
    if not all(file_hash(p) == h for p, h in hashes.items()):
        raise ValueError('upstream_changed_during_view_creation')
    return view, hashes


def export(out, events, store, annotations, upstream, provenance):
    """Same v1.1 judgment semantics; index per event to avoid quadratic scans."""
    links = defaultdict(dict)
    claims = defaultdict(list)
    for key, link in store.links.items():
        links[link['event_id']][key] = link
    for a in annotations:
        claims[a.get('event_id')].append(a)
    original = v11.judge

    def indexed(event, ignored_store, ignored_annotations):
        subset = v11.EvidenceStore()
        subset.evidence = store.evidence
        subset.links = links[event['event_id']]
        result = original(event, subset, claims[event['event_id']])
        store.missing.extend(subset.missing)
        return result

    v11.judge = indexed
    try:
        result = v11.export(out, events, store, annotations, upstream, provenance)
    finally:
        v11.judge = original
    result['version'] = 'agent-log-motivation-1.2'
    result['upstream_snapshot'] = provenance.get('upstream_snapshot')
    result['coverage_interpretation'] = 'source coverage is association/context availability, not motive confirmation'
    write_json(Path(out) / 'summary.json', result)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--workspace', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--trace-run', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--swechat-frozen', type=Path)
    ap.add_argument('--external-cache', type=Path)
    ap.add_argument('--external-failures', type=Path)
    ap.add_argument('--annotations', type=Path)
    ap.add_argument('--reuse-guarded-view', type=Path, help='Prior v1.2 output: revalidate and copy its exact anchor view')
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.workspace / 'src'))
    from agentlog_unified.github_client import GitHubClient
    from align_swechat_agent_logs import Guard
    from swechat_connector_cache import install
    guard = Guard(args.workspace)
    provenance = {'executed_at': datetime.now(timezone.utc).isoformat(), 'script_sha256': file_hash(__file__),
                  'base_implementation_sha256': file_hash(v11.__file__), 'remote_operations': 'GET_only', 'online_requested': False}
    if args.reuse_guarded_view:
        prior = json.loads((args.reuse_guarded_view / 'summary.json').read_text(encoding='utf-8'))
        hashes = prior['provenance']['input_sha256']
        view_hashes = prior['provenance']['trace_view_sha256']
        prior_view = Path(prior['provenance']['trace_view_path'])
        if not all(file_hash(p) == h for p, h in hashes.items()) or not all(file_hash(prior_view / n) == h for n, h in view_hashes.items()):
            raise ValueError('prior_view_or_upstream_changed')
        view = prior_view
        # The same immutable input path preserves event IDs across enrichments.
    else:
        view, hashes = prepare_view(args.trace_run, args.output, guard)
    events, details, gaps, upstream = v11.normalize_trace(view, guard)
    for e in events:
        if not e.get('repository'):
            e['stage1_log_ids'], e['stage1_attribution'], e['upstream_attribution'] = [], [], {}
    store = v11.EvidenceStore()
    store.missing.extend(gaps)
    provenance['input_sha256'] = hashes
    provenance['trace_view_sha256'] = {p.name: file_hash(p) for p in view.glob('*.jsonl')}
    provenance['trace_view_path'] = str(view.resolve())
    if (args.trace_run / 'summary.json').exists():
        provenance['upstream_snapshot'] = json.loads((args.trace_run / 'summary.json').read_text(encoding='utf-8'))
    cache = args.output / 'external_cache'
    if args.external_cache:
        shutil.copytree(args.external_cache, cache)
    client = GitHubClient(cache, offline=True)
    install(client, args.external_failures)
    collector = Collector(client, store)
    for i, e in enumerate(events, 1):
        if e['guard_status'] == 'allowed':
            collector.collect(e, details[e['event_id']])
        if i % 100 == 0 or i == len(events):
            write_json(args.output / 'progress.json', {'stage': 'evidence_replay', 'processed': i, 'total': len(events)})
    allowed = [e for e in events if e['guard_status'] == 'allowed']
    write_json(args.output / 'progress.json', {'stage': 'prompt_join', 'events': len(allowed)})
    dependencies = args.workspace / 'outputs/swechat_log_alignment_20260921/dependencies'
    if dependencies.exists():
        sys.path.insert(0, str(dependencies))
    try:
        v11.collect_prompts(allowed, args.swechat_frozen, store)
    except (ImportError, OSError, ValueError, KeyError) as exc:
        for e in allowed:
            store.gap(e, 'prompt', 'prompt_source_read_failed', error_type=type(exc).__name__, detail=str(exc)[:500])
    provenance['guard_calls'] = dict(guard.calls)
    provenance['inputs_unchanged'] = all(file_hash(p) == h for p, h in hashes.items())
    if not provenance['inputs_unchanged']:
        raise ValueError('upstream_changed_during_collection')
    annotations = [r for _, r in rows(args.annotations)] if args.annotations else []
    if args.annotations:
        provenance['annotations'] = {'path': str(args.annotations.resolve()), 'sha256': file_hash(args.annotations)}
    summary = export(args.output, events, store, annotations, upstream, provenance)
    table(args.output, 'request_outcomes', [{'endpoint': k[0], 'paginated': k[1], 'status': 'failed_or_partial' if failures else 'retrieved',
        'failures': failures, 'returned_rows': len(value) if isinstance(value, list) else None} for k, (value, failures) in collector.cache.items()], ['endpoint', 'status', 'returned_rows', 'failures'])
    write_json(args.output / 'progress.json', {'stage': 'complete', 'events': len(events)})
    write_json(args.output / 'manifest.json', {'version': '1.2', 'artifacts': {p.name: file_hash(p) for p in args.output.iterdir() if p.is_file()}})
    print(v11.canonical({k: summary[k] for k in ('events', 'evidence_rows', 'links', 'motive_distribution')}), flush=True)


if __name__ == '__main__':
    main()
