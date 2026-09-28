import hashlib
import json
import sqlite3

import pytest

from agentlog_unified.corpus_coverage import audit_corpus


def frozen_import(tmp_path, evidence):
    imported = tmp_path / 'imported'
    imported.mkdir()
    with sqlite3.connect(imported / 'aidev.sqlite') as db:
        db.execute('CREATE TABLE prs(pr_key TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE pr_commit_evidence(pr_key TEXT,sha TEXT)')
        db.executemany('INSERT INTO prs VALUES (?)', [(key,) for key in evidence])
        db.executemany('INSERT INTO pr_commit_evidence VALUES (?,?)',
                       [(key, sha) for key, shas in evidence.items() for sha in shas])
    (imported / 'coverage.json').write_text(json.dumps({'aidev_source_snapshot': 'fixture'}))
    (imported / 'manifest.json').write_text(json.dumps({'status': 'complete', 'outputs': {
        name: hashlib.sha256((imported / name).read_bytes()).hexdigest()
        for name in ('aidev.sqlite', 'coverage.json')}}))
    return imported


def test_corpus_join_requires_real_commit_overlap_and_deduplicates_runs(tmp_path):
    imported=tmp_path/'imported'; imported.mkdir()
    sha='a'*40
    with sqlite3.connect(imported/'aidev.sqlite') as db:
        db.execute('CREATE TABLE prs(pr_key TEXT PRIMARY KEY)')
        db.executemany('INSERT INTO prs VALUES (?)', [('owner/repo#1',), ('owner/repo#2',), ('owner/repo#3',)])
        db.execute('CREATE TABLE pr_commit_evidence(pr_key TEXT,sha TEXT)')
        db.executemany('INSERT INTO pr_commit_evidence VALUES (?,?)', [('owner/repo#1',sha), ('owner/repo#2',sha)])
    (imported/'coverage.json').write_text(json.dumps({'aidev_source_snapshot':'fixture'}))
    (imported/'manifest.json').write_text(json.dumps({'status':'complete','outputs':{
        name:hashlib.sha256((imported/name).read_bytes()).hexdigest() for name in ('aidev.sqlite','coverage.json')}}))
    runs=[]
    for i in range(2):
        run=tmp_path/f'run{i}'; (run/'data').mkdir(parents=True); runs.append(run)
        rows=[]
        for number in (1,2,99):
            rows.append({'pr_id':str(number),'unit':'GitHub_PR','repository':'Owner/Repo','pr_number':number,
                'git_evidence_shas':[sha if number==1 else 'b'*40],
                'analysis_snapshot_shas':[sha if number==1 else 'b'*40],
                'analyzed_in_supported_scope':True,'coverage_status':'partial',
                'has_observed_type_labels':True,'has_unknown_type_review':True})
        (run/'data/pr_coverage_audit.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    output=tmp_path/'audit'
    assert audit_corpus(imported,runs,output,dry_run=True)['files_written'] is False
    assert not output.exists()
    result=audit_corpus(imported,runs,output)
    assert result['counts']=={
        'dataset_unique_prs':3,'dataset_prs_selected_in_runs':2,
        'dataset_prs_with_analyzed_commit_overlap':1,
        'dataset_prs_with_all_commits_analyzed_in_one_run':1,
        'analysis_prs_not_in_dataset':1,'dataset_prs_without_verified_commit_analysis':2}
    links=[json.loads(r) for r in (output/'analyzed_pr_links.jsonl').read_text().splitlines()]
    assert all(r['has_observed_type_labels'] is None for r in links if r['pr_id']=='2')
    assert all(r['runtime_confirmed'] is False for r in links)
    with pytest.raises(ValueError,match='already exists'):
        audit_corpus(imported,runs,output)
    (imported/'coverage.json').write_text('{}')
    with pytest.raises(ValueError,match='was changed'):
        audit_corpus(imported,runs,tmp_path/'tampered')


def test_batch_join_actual_pydriller_sources_pending_jobs_and_context_identity(tmp_path):
    from agentlog_unified import batch_mine as batch
    from synthetic_histories import HEADER, commit, init
    repo = tmp_path / 'repo'
    init(repo)
    bad = commit(repo, {'app.py': 'def broken(\n'}, 'invalid old source')
    sha = commit(repo, {'app.py': HEADER + 'logger.info("password=%s", user.password)\n'
                       'logger.info("unknown=%s", mystery)\n'}, 'valid source', day=3)
    # A partial commit with a before-side parse failure still has valid after evidence.
    imported = frozen_import(tmp_path, {'fixture/project#1': [sha], 'fixture/project#2': [bad],
                                       'fixture/project#3': []})
    source = tmp_path / 'contexts.jsonl'
    context = {'dataset': 'aidev', 'repository': 'fixture/project', 'sha': sha,
               'source_pr_key': 'fixture/project#1', 'aidev_source_snapshot': 'fixture',
               'local_repo_path': str(repo)}
    source.write_text(json.dumps(context) + '\n')
    output = tmp_path / 'batch'
    batch.ingest_commit_contexts(source, output)
    batch.run_batch(output, tmp_path / 'cache')
    source.write_text(json.dumps({**context, 'sha': bad, 'source_pr_key': 'fixture/project#2'}) + '\n')
    batch.ingest_commit_contexts(source, output)  # selected and pending, never analyzed
    wrong_contexts = [
        ({'dataset': 'swe-chat'}, 'non_aidev_context'),
        ({'is_synthetic': True}, 'calibration_context'),
        ({'aidev_source_snapshot': 'other'}, 'aidev_snapshot_missing_or_mismatch'),
        ({'source_pr_key': 'other/project#1'}, 'pr_repository_identity_mismatch'),
        ({'sha': bad}, 'context_commit_identity_mismatch'),
        ({'source_pr_key': 'fixture/project#99'}, 'pr_not_in_frozen_aidev'),
        ({'source_pr_key': 'fixture/project#3'}, 'commit_not_in_frozen_pr_evidence'),
    ]
    with sqlite3.connect(output / 'batch.sqlite') as db:
        for index, (overrides, _) in enumerate(wrong_contexts):
            db.execute('INSERT INTO contexts VALUES (?,?,?,?)',
                       (str(index), 'fixture/project', sha, json.dumps({**context, **overrides})))
    report = audit_corpus(imported, [output], tmp_path / 'audit')
    counts = report['counts']
    assert counts['dataset_unique_prs'] == 3
    assert counts['dataset_prs_selected_in_runs'] == 2
    assert counts['dataset_prs_without_verified_commit_analysis'] == 2
    for metric in ('analyzed_commit_overlap', 'git_commit_evidence', 'git_source_evidence',
                   'supported_language_source', 'log_observations', 'observed_type_labels',
                   'unknown_type_review', 'partial_batch_jobs', 'pending_batch_jobs'):
        assert counts['dataset_prs_with_' + metric] == 1, metric
    assert counts['dataset_prs_with_complete_batch_jobs'] == 0
    assert report['batch_context_exclusion_counts'] == {reason: 1 for _, reason in wrong_contexts}
    assert report['full_history_tracing_completed_by_batch'] is False
    links = {row['source_pr_key']: row for row in map(json.loads, (tmp_path / 'audit/analyzed_pr_links.jsonl').read_text().splitlines())}
    assert links['fixture/project#1']['run_coverage_status'] == 'partial'
    assert links['fixture/project#1']['git_evidence_shas'] == [sha]
    assert links['fixture/project#2']['has_observed_type_labels'] is None
    assert all(row['human_review_status'] == 'pending' and not row['runtime_confirmed'] for row in links.values())


@pytest.mark.parametrize('case,git,source,analyzed,typed', [
    ('valid_deleted_side', True, True, True, True),
    ('wrong_snapshot_side', True, True, True, False),
    ('wrong_merge_parent', True, True, True, False),
    ('wrong_job_identity', False, False, False, False),
    ('pending', False, False, False, False),
    ('running', False, False, False, False),
    ('blocked', False, False, False, False),
    ('missing_source', True, False, False, False),
    ('unsupported_language', True, True, False, False),
    ('missing_diff', True, True, False, False),
    ('parse_failure', True, True, False, False),
    ('lexical_source_unavailable', True, True, False, False),
])
def test_batch_evidence_requires_exact_source_side_and_parent(tmp_path, case, git, source, analyzed, typed):
    from agentlog_unified.corpus_coverage import _batch_commit_evidence
    sha, parent, other = 'a' * 40, 'b' * 40, 'c' * 40
    metadata = {'repository': 'fixture/project', 'sha': sha, 'parents': [parent, other],
                'metrics': {'pydriller_commits': 1, 'pydriller_source_reads': 1,
                            'pydriller_diff_parsed_calls': 1}}
    audit = {'sha': sha, 'parent_sha': parent, 'old_path': 'app.py', 'new_path': None,
             'source_status': {'before': 'ok'}, 'before_source_fingerprint': 'fixture-fingerprint',
             'analysis_status': 'supported_language', 'diff': '-logger.info(user.password)'}
    log = {'sha': sha, 'parent_sha': parent, 'snapshot_sha': parent, 'side': 'before',
           'entity': {'path': 'app.py', 'taxonomy_labels': ['AUTH.password']}}
    if case == 'wrong_snapshot_side':
        log['snapshot_sha'] = sha
    if case == 'wrong_merge_parent':
        log.update(parent_sha=other, snapshot_sha=other)
    if case == 'wrong_job_identity':
        metadata['sha'] = other
    if case == 'missing_source':
        audit['before_source_fingerprint'] = None
    if case == 'unsupported_language':
        audit['analysis_status'] = 'unsupported_language'
    if case == 'missing_diff':
        audit['diff'] = None
    status = case if case in {'pending', 'running', 'blocked'} else 'partial'
    with sqlite3.connect(':memory:') as db:
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE records(repository TEXT, sha TEXT, kind TEXT, data TEXT)')
        records = [('file_audit', audit), ('log_observations', log)]
        if case == 'parse_failure':
            records.append(('gaps', {'sha': sha, 'parent_sha': parent, 'side': 'before',
                                    'path': 'app.py', 'reason': 'python_ast_parse_failed'}))
        if case == 'lexical_source_unavailable':
            records.append(('gaps', {'sha': sha, 'parent_sha': parent, 'side': 'before',
                                    'path': 'app.py', 'reason': 'synthetic_lexical_boundary_failure',
                                    'source_analysis_unavailable': True}))
        db.executemany('INSERT INTO records VALUES (?,?,?,?)',
                       [('fixture/project', sha, kind, json.dumps(row)) for kind, row in records])
        result = _batch_commit_evidence(db, 'fixture/project', sha, status, metadata)
    assert (result['git'], result['source'], result['analyzed'], result['typed']) == (git, source, analyzed, typed)


def test_batch_audit_rejects_active_writer_without_changing_inputs(tmp_path):
    import fcntl
    from agentlog_unified.corpus_coverage import _batch_read
    directory = tmp_path / 'batch'
    directory.mkdir()
    database = directory / 'batch.sqlite'
    database.touch()
    with (directory / '.batch.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match='writer is active'):
            with _batch_read(database):
                pytest.fail('active writer was not rejected')
    assert database.stat().st_size == 0
