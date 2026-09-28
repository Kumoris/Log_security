"""Prepare a bounded two-dataset pilot; reuse semantic-scan, DFG and assessment.

Selection uses existing log-change coordinates, never sensitive labels. Existing
batch coverage limits the frame. Source contexts remain separate from authorship.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

from agentlog_unified.config import sha256_file
from agentlog_unified.batch_mine import repository_cache_path
from agentlog_unified.export import write_json, write_jsonl
from agentlog_unified.semantic_context import HistoricalContext, load_run
from mine_aidev_reference_types import finish, start, tables

SEED = 20260911


def eligible(observations):
    frame = {}
    for row in observations:
        path = row['entity']['path']
        extension = Path(path).suffix
        if (row['side'] != 'after' or row['change_basis'] != 'statement_lines'
                or extension not in {'.py', '.go', '.ts', '.tsx', '.js'}
                or any(s in path.lower() for s in ('test', 'fixture', 'example', 'mock', 'demo', 'debug'))):
            continue
        frame.setdefault((row['repository'], row['sha']), set()).add(extension)
    return frame


def choose(frame):
    selected = []
    for extension in ('.py', '.go', '.ts'):
        group = [key for key, extensions in frame.items()
                 if extension in extensions and key[0] not in {r[0] for r in selected}]
        if group:
            selected.append(min(group, key=lambda k: hashlib.sha256((str(SEED)+str(k)).encode()).hexdigest()))
    return selected


def prepare(project, output):
    if output.exists():
        raise ValueError('new_pilot_directory_required')
    cache_map = {}
    for base in ('object-repos', 'batch-repos', 'semantic-full-v070', 'anchor-object-repos', 'repos'):
        for path in sorted((project/'data/cache'/base).iterdir()):
            if not path.is_dir():
                continue
            remote = subprocess.run(['git', '-C', str(path), 'config', '--get', 'remote.origin.url'],
                                    capture_output=True, text=True, check=False).stdout.strip()
            repository = remote.removesuffix('.git').split('github.com/')[-1].split('github.com:')[-1].lower()
            if '/' in repository:
                cache_map.setdefault(repository, []).append(path.resolve())
    for dataset in ('aidev', 'swechat'):
        database = project/'outputs/batches'/f'{dataset}-full-v5/batch.sqlite'
        db = sqlite3.connect(f'file:{database.resolve()}?mode=ro', uri=True)
        try:
            observations = [json.loads(r[0]) for r in db.execute("SELECT data FROM records WHERE kind='log_observations'")]
            frame = eligible(observations)
            selected = choose(frame)
            inputs, contexts = [], []
            for repository, sha in selected:
                local = None
                candidates = [repository_cache_path(project/'data/cache'/base, repository)
                              for base in ('object-repos','batch-repos','anchor-object-repos')]
                for path in candidates + cache_map.get(repository, []):
                    if not path.is_dir():
                        continue
                    found = subprocess.run(['git', '-C', str(path), 'cat-file', '-e', sha+'^{commit}'],
                                           capture_output=True, env={**os.environ, 'GIT_NO_LAZY_FETCH':'1'})
                    if found.returncode == 0:
                        local = path
                        break
                if local is None:
                    raise ValueError(f'fixed_selected_commit_unavailable:{repository}@{sha}')
                source = [json.loads(r[0]) for r in db.execute('SELECT data FROM contexts WHERE repository=? AND sha=?', (repository, sha))]
                if not source or any(r['dataset'].lower().replace('-', '') != dataset for r in source):
                    raise ValueError('source_dataset_binding_missing_or_wrong')
                contexts.extend(source)
                inputs.append({'repository':repository, 'commit_shas':[sha], 'initial_commit_shas':[sha],
                               'target_ref':sha, 'local_repo_path':str(local), 'is_synthetic':False,
                               'provenance_evidence':[], 'pr_actor_type':'unknown',
                               'metadata_source':dataset+'_frozen_batch_context',
                               'sampling_reason':'existing_changed_application_log_commit_language_strata_no_sensitive_filter'})
            out = output/dataset
            tables(out, {'source_contexts':contexts,
                         'commit_sampling_frame':[{'repository':r,'sha':s,'extensions':sorted(v),'selected':(r,s) in selected}
                                                  for (r,s),v in sorted(frame.items())]})
            write_jsonl(out/'input.jsonl', inputs)
            write_json(out/'selection.json', {'dataset':dataset, 'seed':SEED, 'batch_database':str(database.resolve()),
                       'batch_database_sha256':sha256_file(database), 'existing_log_observations':len(observations),
                       'eligible_commits':len(frame), 'selected_commits':selected,
                       'selected_without_sensitive_labels':True, 'actor_labels_verified':False,
                       'selection_bias':'available_previously_mined_log_changes; not a prevalence or recall sample'})
        finally:
            db.close()
    write_json(output/'config.json', {'random_seed':SEED,'semantics':{'max_fields':30, 'max_history_commits':1,
               'max_snapshot_files':200,'max_source_bytes':262144,'max_context_chars':24000,
               'max_hops':2,'ablations':False,'development_only':True}})
    print(json.dumps({'status':'prepared','output':str(output),'datasets':2,'commits_per_dataset':3}))


def normalize(run, output, resume=False):
    # Adapt existing semantic-scan evidence to the existing reference assessor.
    fp, done = start(output, [run/'manifest.json'], {'stage':'pilot_normalize','runner':sha256_file(Path(__file__))}, resume, False)
    if done:
        return done
    cases, snapshots, _ = load_run(run)
    for key, case in cases.items():
        row = case['result']
        row['fixture_or_tutorial_path'] = row.get('fixture_context', False) or any(
            part.lower() in {'templates','template','examples','example','mocks','mock'}
            for part in Path(row['path']).parts)
        case['reference_ids'] = []
        case['sampling_scope'] = 'dataset_commit_changed_log_before_or_after_actor_unknown'
        context = HistoricalContext(case, snapshots[row['repository'],row['sha']])
        state = context.initial(24000)
        if state['status'] not in {'success','truncated'}:
            raise ValueError('historical_context_unavailable:'+key)
        case['supplementary_context'] = {'blocks':context.blocks,'initial_status':state,
                                        'missing':[{'reason':g.get('reason','snapshot_gap')}
                                                   for g in context.snapshot.get('gaps',[])]}
        write_json(output/'evidence'/(key+'.json'), case)
    shutil.copy2(run/'checkpoint.sqlite', output/'checkpoint.sqlite')
    return finish(output, fp, {'field_uses':len(cases), 'by_side':dict(Counter(c['result']['side'] for c in cases.values())),
                              'selection':'unchanged_semantic_scan_sample','human_labels':0})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare','normalize'])
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--resume',action='store_true')
    args = parser.parse_args()
    if args.stage == 'prepare':
        prepare(args.input.resolve(), args.output.resolve())
    else:
        print(json.dumps(normalize(args.input,args.output,args.resume)))
