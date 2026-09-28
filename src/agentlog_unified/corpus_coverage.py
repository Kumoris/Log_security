"""Join a frozen AIDev census to actual run evidence without reading PR bodies."""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from contextlib import contextmanager
from itertools import groupby
from pathlib import Path

from .config import sha256_file
from .export import write_csv, write_json, write_jsonl


@contextmanager
def _batch_read(path):
    """Use the existing batch lock without creating or writing any input file."""
    import fcntl
    lock = (path.parent / '.batch.lock').open('rb') if (path.parent / '.batch.lock').exists() else None
    connection = None
    try:
        if lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Batch writer is active; audit its completed checkpoint after it stops') from None
        with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True) as db:
            connection = db
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            yield db
    finally:
        if connection:
            connection.close()
        if lock:
            lock.close()


def _batch_commit_evidence(db, repository, sha, status, metadata):
    """Differentiate commit reads, source reads, analyzable files and log evidence."""
    metrics = metadata.get('metrics', {})
    git = (status in {'complete', 'partial'} and metrics.get('pydriller_commits', 0) > 0
           and metadata.get('repository') == repository and metadata.get('sha') == sha)
    if not git:
        return dict.fromkeys(('git', 'source', 'supported_source', 'analyzed', 'typed', 'unknown', 'logs'), False)
    parents = set(metadata.get('parents', [])) or {None}
    source_pairs, supported_pairs, analyzable_pairs, failures, logs = set(), set(), set(), [], []
    for row in db.execute("""SELECT kind,
      json_extract(data,'$.sha') record_sha,json_extract(data,'$.parent_sha') parent_sha,
      json_extract(data,'$.analysis_status') analysis_status,json_extract(data,'$.source_status') source_status,
      json_type(data,'$.diff')='text' diff_available,
      json_extract(data,'$.before_source_fingerprint') before_fingerprint,json_extract(data,'$.after_source_fingerprint') after_fingerprint,
      json_extract(data,'$.old_path') old_path,json_extract(data,'$.new_path') new_path,
      json_extract(data,'$.reason') reason,json_extract(data,'$.side') side,json_extract(data,'$.path') path,
      json_extract(data,'$.source_analysis_unavailable') source_analysis_unavailable,
      json_extract(data,'$.snapshot_sha') snapshot_sha,json_extract(data,'$.entity.path') log_path,
      json_array_length(json_extract(data,'$.entity.taxonomy_labels')) type_count,
      json_extract(data,'$.entity.unknown_type_review.needs_review') unknown_review,
      json_array_length(json_extract(data,'$.entity.unknown_type_review.reasons')) unknown_reasons,
      json_extract(data,'$.entity.taxonomy_status') taxonomy_status
      FROM records WHERE repository=? AND sha=? AND kind IN ('file_audit','log_observations','gaps')""", (repository, sha)):
        if row['record_sha'] != sha:
            continue
        if row['kind'] == 'file_audit' and row['parent_sha'] in parents:
            statuses = json.loads(row['source_status'] or '{}')
            for side, path, fingerprint in (('before', row['old_path'], row['before_fingerprint']), ('after', row['new_path'], row['after_fingerprint'])):
                if path and fingerprint and statuses.get(side) == 'ok':
                    pair = (path, side, row['parent_sha'])
                    source_pairs.add(pair)
                    if row['analysis_status'] == 'supported_language':
                        supported_pairs.add(pair)
                        if row['diff_available'] and metrics.get('pydriller_diff_parsed_calls', 0) > 0:
                            analyzable_pairs.add(pair)
        elif row['kind'] == 'gaps':
            if row['reason'] == 'snapshot_detection_error':
                failures.append((None, row['side'], row['parent_sha']))
            if (row['reason'] in {'python_ast_parse_failed', 'unbalanced_log_call'} or row['source_analysis_unavailable']) and row['path']:
                failures.append((row['path'], row['side'], row['parent_sha']))
        elif row['kind'] == 'log_observations':
            logs.append((row['snapshot_sha'], row['log_path'], row['side'], row['parent_sha'], bool(row['type_count']), bool(row['unknown_review'] or row['unknown_reasons'] or row['taxonomy_status'] == 'needs_review')))
    source = git and metrics.get('pydriller_source_reads', 0) > 0 and bool(source_pairs)
    # A failure without a parent is conservatively applied to every comparison,
    # but a before-side parse failure must not erase a successful after-side read.
    available = {pair for pair in analyzable_pairs if not any(
        all(value is None or value == actual for value, actual in zip(failure, pair)) for failure in failures)}
    analyzed = source and bool(available)
    observed = [row for row in logs if row[0] == (sha if row[2] == 'after' else row[3])
                and (row[1], row[2], row[3]) in available] if analyzed else []
    return {'git': git, 'source': source, 'supported_source': source and bool(supported_pairs), 'analyzed': analyzed,
            'typed': any(row[4] for row in observed), 'unknown': any(row[5] for row in observed), 'logs': bool(observed)}


def _batch_links(path, source_db, snapshot):
    entries, exclusions, expected_cache = {}, [], {}
    with _batch_read(path) as db:
        cursor = db.execute("""SELECT c.id,c.repository,c.sha,c.data,j.status job_status,j.data job_data FROM contexts c
          LEFT JOIN jobs j ON j.repository=c.repository AND j.sha=c.sha ORDER BY c.repository,c.sha,c.id""")
        for (repository, sha), contexts in groupby(cursor, lambda row: (row['repository'], row['sha'])):
            evidence = None
            for stored in contexts:
                context = json.loads(stored['data'])
                key, reason = context.get('source_pr_key'), None
                dataset = str(context.get('dataset', '')).lower().replace('-', '')
                if dataset != 'aidev':
                    reason = 'non_aidev_context'
                elif context.get('is_synthetic') or context.get('cohort') == 'calibration_only':
                    reason = 'calibration_context'
                elif not snapshot or context.get('aidev_source_snapshot') != snapshot:
                    reason = 'aidev_snapshot_missing_or_mismatch'
                elif not isinstance(key, str) or '#' not in key or key.rsplit('#', 1)[0].lower() != repository.lower() or context.get('repository', '').lower() != repository.lower():
                    reason = 'pr_repository_identity_mismatch'
                elif context.get('sha') != sha:
                    reason = 'context_commit_identity_mismatch'
                if reason is None:
                    key = key.lower()
                    if key not in expected_cache:
                        present = source_db.execute('SELECT 1 FROM prs WHERE pr_key=?', (key,)).fetchone() is not None
                        expected_cache[key] = ({value for value, in source_db.execute('SELECT sha FROM pr_commit_evidence WHERE pr_key=?', (key,))} if present else None)
                    expected = expected_cache[key]
                    if expected is None:
                        reason = 'pr_not_in_frozen_aidev'
                    elif sha not in expected:
                        reason = 'commit_not_in_frozen_pr_evidence'
                if reason:
                    exclusions.append({'run_dir': str(path.parent), 'context_id': stored['id'], 'source_pr_key': key,
                                       'repository': repository, 'sha': sha, 'reason': reason, 'runtime_confirmed': False})
                    continue
                if evidence is None:
                    evidence = _batch_commit_evidence(db, repository, sha, stored['job_status'], json.loads(stored['job_data'] or '{}'))
                entry = entries.setdefault(key, {'source_pr_key': key, 'run_dir': str(path.parent), 'pr_id': key,
                    'source_kind': 'dataset_commit_batch', 'source_snapshot_verified': True, 'present_in_aidev': True,
                    'dataset_commit_count': len(expected), 'selected': set(), 'git': set(), 'source': set(),
                    'supported_source': set(), 'analyzed': set(), 'typed': set(), 'unknown': set(), 'logs': set(), 'statuses': set()})
                entry['selected'].add(sha)
                entry['statuses'].add(stored['job_status'] or 'job_missing')
                for field, present in evidence.items():
                    if present:
                        entry[field].add(sha)
    records = []
    for key, entry in sorted(entries.items()):
        analyzed = entry['analyzed']
        record = {key: value for key, value in entry.items() if not isinstance(value, set)}
        record.update(dataset_commits_analyzed_count=len(analyzed), has_dataset_commit_analysis=bool(analyzed),
            all_dataset_commits_analyzed=bool(expected_cache[key]) and expected_cache[key] <= analyzed,
            run_coverage_status='not_analyzed' if not analyzed else 'bounded_complete' if entry['statuses'] == {'complete'} and expected_cache[key] <= analyzed else 'partial',
            job_statuses=sorted(entry['statuses']), selected_dataset_shas=sorted(entry['selected']), git_evidence_shas=sorted(entry['git']),
            git_source_evidence_shas=sorted(entry['source']), supported_language_source_shas=sorted(entry['supported_source']),
            supported_analysis_shas=sorted(analyzed), typed_log_commit_shas=sorted(entry['typed']), unknown_type_commit_shas=sorted(entry['unknown']),
            has_dataset_git_commit_evidence=bool(entry['git']), has_dataset_git_source_evidence=bool(entry['source']),
            has_supported_language_source_evidence=bool(entry['supported_source']), has_dataset_log_observations=bool(entry['logs']),
            has_observed_type_labels=bool(entry['typed']) if analyzed else None, has_unknown_type_review=bool(entry['unknown']) if analyzed else None,
            runtime_confirmed=False, human_review_status='pending', observation_scope='dataset_commit_changes', full_history_tracing_completed=False,
            analysis_basis='Successful PyDriller commit/source reads, supported source fingerprints and no recorded parser/detection failure for the observed path/side')
        records.append(record)
    return records, exclusions


def audit_corpus(import_dir: Path, run_dirs: list[Path], output_dir: Path, *, dry_run=False):
    source, output = Path(import_dir).resolve(), Path(output_dir).resolve()
    runs = sorted({Path(path).resolve() for path in run_dirs})
    if not runs:
        raise ValueError('At least one --analysis-run is required')
    inputs = [source, *runs]
    if any(output == p or p in output.parents or output in p.parents for p in inputs):
        raise ValueError('Coverage output must be separate from input/import/run directories')
    if output.exists():
        raise ValueError('Coverage output already exists; choose a new directory')
    manifest = json.loads((source/'manifest.json').read_text())
    if manifest.get('status') != 'complete':
        raise ValueError('A completed AIDev import is required')
    for name in ('aidev.sqlite', 'coverage.json'):
        if sha256_file(source/name) != manifest.get('outputs', {}).get(name):
            raise ValueError('Frozen AIDev import was changed')
    census = json.loads((source/'coverage.json').read_text())
    paths = [path/'batch.sqlite' if (path/'batch.sqlite').is_file() else path/'data/pr_coverage_audit.jsonl' for path in runs]
    if any(not path.is_file() for path in paths):
        raise ValueError('Analysis inputs must contain batch.sqlite or export pr_coverage_audit.jsonl')
    if dry_run:
        return {'dry_run': True, 'files_written': False, 'network_accessed': False,
                'import': str(source), 'analysis_runs': [str(p) for p in runs]}
    versions = {}
    records = []
    exclusions = []
    grouped = defaultdict(list)
    with sqlite3.connect((source/'aidev.sqlite').as_uri()+'?mode=ro', uri=True) as db:
        total = db.execute('SELECT COUNT(*) FROM prs').fetchone()[0]
        for path in paths:
            versions[str(path)] = sha256_file(path)
            if path.name == 'batch.sqlite':
                batch_rows, rejected = _batch_links(path, db, census.get('aidev_source_snapshot'))
                records.extend(batch_rows)
                exclusions.extend(rejected)
                for row in batch_rows:
                    grouped[row['source_pr_key']].append(row)
                continue
            with path.open() as stream:
                for line in stream:
                    row = json.loads(line)
                    if row.get('unit') != 'GitHub_PR':
                        continue
                    key = f"{row['repository'].lower()}#{int(row['pr_number'])}"
                    present = db.execute('SELECT 1 FROM prs WHERE pr_key=?', (key,)).fetchone() is not None
                    expected = {sha for sha, in db.execute('SELECT sha FROM pr_commit_evidence WHERE pr_key=?', (key,))}
                    git = set(row.get('git_evidence_shas', []))
                    analyzed = set(row.get('analysis_snapshot_shas', [])) if row.get('analyzed_in_supported_scope') else set()
                    overlap = expected & git & analyzed
                    entry = {'source_pr_key': key, 'run_dir': str(path.parents[1]), 'pr_id': row['pr_id'],
                        'present_in_aidev': present, 'dataset_commit_count': len(expected),
                        'dataset_commits_analyzed_count': len(overlap),
                        'has_dataset_commit_analysis': bool(overlap),
                        'all_dataset_commits_analyzed': bool(expected) and expected <= overlap,
                        'run_coverage_status': row['coverage_status'],
                        'has_observed_type_labels': row['has_observed_type_labels'] if overlap else None,
                        'has_unknown_type_review': row['has_unknown_type_review'] if overlap else None,
                        'has_dataset_git_commit_evidence': bool(expected & git),
                        'has_dataset_git_source_evidence': bool(overlap),
                        'has_supported_language_source_evidence': bool(overlap),
                        'has_dataset_log_observations': bool(overlap and (row.get('initial_log_event_ids') or row.get('has_observed_type_labels') or row.get('has_unknown_type_review'))),
                        'runtime_confirmed': False, 'human_review_status': 'pending'}
                    records.append(entry)
                    if present:
                        grouped[key].append(entry)
        counts = {
            'dataset_unique_prs': total,
            'dataset_prs_selected_in_runs': len(grouped),
            'dataset_prs_with_analyzed_commit_overlap': sum(any(r['has_dataset_commit_analysis'] for r in rows) for rows in grouped.values()),
            'dataset_prs_with_all_commits_analyzed_in_one_run': sum(any(r['all_dataset_commits_analyzed'] for r in rows) for rows in grouped.values()),
            'analysis_prs_not_in_dataset': len({r['source_pr_key'] for r in records if not r['present_in_aidev']} | {r['source_pr_key'] for r in exclusions if r['reason'] == 'pr_not_in_frozen_aidev'}),
        }
        counts['dataset_prs_without_verified_commit_analysis'] = total - counts['dataset_prs_with_analyzed_commit_overlap']
        if any(path.name == 'batch.sqlite' for path in paths):
            for metric, field in (
                ('dataset_prs_with_git_commit_evidence', 'has_dataset_git_commit_evidence'),
                ('dataset_prs_with_git_source_evidence', 'has_dataset_git_source_evidence'),
                ('dataset_prs_with_supported_language_source', 'has_supported_language_source_evidence'),
                ('dataset_prs_with_log_observations', 'has_dataset_log_observations'),
                ('dataset_prs_with_observed_type_labels', 'has_observed_type_labels'),
                ('dataset_prs_with_unknown_type_review', 'has_unknown_type_review')):
                counts[metric] = sum(any(row.get(field) is True for row in rows) for rows in grouped.values())
            for status in ('pending', 'running', 'blocked', 'partial', 'complete', 'job_missing'):
                counts[f'dataset_prs_with_{status}_batch_jobs'] = sum(
                    any(status in row.get('job_statuses', []) for row in rows) for rows in grouped.values())
    report = {'aidev_source_snapshot': census.get('aidev_source_snapshot'), 'counts': counts,
        'denominator': 'distinct PR identities in the frozen multi-table import',
        'analysis_inputs': versions, 'aidev_import': str(source),
        'limitations': ['Metadata/patch ingestion is not Git source analysis.',
            'Matching a PR URL alone is insufficient: dataset commit SHAs must overlap actual Git and analyzed snapshots.',
            'Multiple runs of one PR count once; complete-commit count requires one run covering its dataset commit set.',
            'All-commit coverage can still have parser/language/history gaps; consult per-run code_coverage_audit.',
            'Type labels remain bounded static candidates; no unknown or unexamined PR is marked safe.'],
        'runtime_confirmed': False, 'network_accessed': False}
    if any(path.name == 'batch.sqlite' for path in paths):
        from collections import Counter
        report['batch_context_exclusion_counts'] = dict(Counter(row['reason'] for row in exclusions))
        report['batch_observation_scope'] = 'dataset_commit_changes'
        report['full_history_tracing_completed_by_batch'] = False
        report['limitations'].extend([
            'Batch links require matching AIDev snapshot, PR identity, repository and a frozen PR commit SHA; external/calibration/non-AIDev contexts are excluded.',
            'A queued job or provided metadata is not analysis. Git commit reads, available source, supported source and log-type observations have separate counts.',
            'PR counts by job status overlap when a PR has multiple commits. A running status without a live writer can be an interrupted job and is not verified analysis.',
            'Supported-scope analysis requires actual source fingerprints plus a completed/partial PyDriller job without a recorded detector/parser failure for that path/side.',
            'Batch observations concern supplied commit changes against their parents, including deleted-side logs; they do not trace full follow-up history.'])
    # Fail before publishing if another process replaced an audited input.
    if any(sha256_file(Path(p)) != digest for p, digest in versions.items()):
        raise ValueError('Analysis evidence changed during coverage audit')
    if any(sha256_file(source/name) != manifest['outputs'][name] for name in ('aidev.sqlite', 'coverage.json')):
        raise ValueError('Frozen AIDev import changed during coverage audit')
    output.mkdir(parents=True, mode=0o700)
    write_json(output/'corpus_coverage.json', report)
    write_csv(output/'corpus_coverage.csv', [{'metric': k, 'count': v, 'denominator': total} for k, v in counts.items()])
    write_jsonl(output/'analyzed_pr_links.jsonl', records)
    write_csv(output/'analyzed_pr_links.csv', records)
    if any(path.name == 'batch.sqlite' for path in paths):
        write_jsonl(output/'analysis_input_exclusions.jsonl', exclusions)
        write_csv(output/'analysis_input_exclusions.csv', exclusions,
                  ['run_dir', 'context_id', 'source_pr_key', 'repository', 'sha', 'reason', 'runtime_confirmed'])
    return report
