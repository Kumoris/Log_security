"""Build versioned log events before any privacy ranking."""
from __future__ import annotations
from collections import defaultdict
from functools import lru_cache
from .detector import detect_snapshot
from .matching import behavior, entity_key, match_cross_file, match_entities, resolve_match
from .miner import snapshot_files
from .storage import stable_id


def detect_history(repository: dict, mined: dict, config: dict, match_overrides: list[dict] | None = None, *, snapshot_consumer=None, snapshot_seeds=None) -> dict:
    path = repository['local_repo_path']
    rid = repository['id']
    gaps, events, snapshots, audit = [], [], {}, []
    mining = config['mining']
    @lru_cache(maxsize=64)
    def snapshot(sha: str | None) -> list[dict]:
        if sha is None:
            return []
        raw = snapshot_files(path,sha,max_files=mining['max_snapshot_files'],max_source_bytes=mining['max_source_file_bytes'],extensions=mining.get('snapshot_extensions'))
        recovered=set()
        for file_path,seed in (snapshot_seeds or {}).get(sha,{}).items():
            if file_path not in raw['files']:
                raw['files'][file_path]=seed['source']
                raw.setdefault('file_provenance',{})[file_path]={k:v for k,v in seed.items() if k!='source'}
                recovered.add(file_path)
        parsed = detect_snapshot(raw['files'],config['languages'])
        if config.get('semantic_context_dependencies'):
            from .semantic_bindings import reference_files
            # Explicit same-revision references are possible context dependencies.
            # They are not themselves proof of a field's meaning or a leak.
            for entity in parsed['entities']:
                for dependency,source in reference_files(raw['files'],entity['path']).items():
                    entity['dependencies'].append({'path':dependency,'symbol':'<explicit_schema_or_document_reference>',
                        'start_line':1,'end_line':len(source.splitlines()),'code':source,
                        'kind':'explicit_context_reference','binding_status':'requires_semantic_evidence_replay'})
        if snapshot_consumer is not None:
            snapshot_consumer(sha, raw)
        for gap in raw['gaps'] + parsed['gaps']:
            gaps.append({'error_type':gap.get('error_type') or gap.get('kind') or gap.get('reason') or 'parser_coverage_gap','retryable':False,**gap,'stage':'detect','sha':sha,'repository_id':rid,'repository':repository['repository_id']})
        unavailable = {g['path'] for g in raw['gaps'] if g.get('path')} - recovered
        unavailable.update(g['path'] for g in parsed['gaps'] if g.get('path') and
                           (g.get('reason') in {'python_ast_parse_failed', 'unbalanced_log_call'} or
                            g.get('source_analysis_unavailable')))
        snapshots[sha] = {'id':stable_id(rid,sha),'repository_id':rid,'sha':sha,'entities':parsed['entities'],'source_backend':raw['backend'],'fallback_reason':raw['fallback_reason'],'reverse_dependency_coverage':'partial' if raw['gaps'] or parsed['gaps'] else 'bounded_supported_extensions','unavailable_paths':sorted(unavailable),'whole_snapshot_unavailable':any(not g.get('path') for g in raw['gaps']),'available_paths':sorted(raw['files'])}
        return parsed['entities']
    by_commit = defaultdict(list)
    for change in mined['changes']:
        by_commit[change['sha']].append(change)
    gap_states = {}
    applied_overrides = set()
    for commit in mined['commits']:
        sha = commit['sha']
        parents = commit['parents']
        parent = parents[0] if parents else None
        # Other merge parents are retained as raw evidence; only first-parent net
        # changes define this commit's integration events, preventing duplication.
        changes = [c for c in by_commit[sha] if c['parent_sha'] == parent]
        old, new = snapshot(parent),snapshot(sha)
        renames = {c['old_path']:c['new_path'] for c in changes if c['old_path'] and c['new_path'] and c['old_path']!=c['new_path']}
        old_bad = set(snapshots.get(parent, {}).get('unavailable_paths', []))
        new_bad = set(snapshots[sha]['unavailable_paths'])
        if snapshots.get(parent, {}).get('whole_snapshot_unavailable'):
            old_bad.update(e['path'] for e in old + new if e['path'] not in snapshots[parent]['available_paths'])
        if snapshots[sha]['whole_snapshot_unavailable']:
            new_bad.update(e['path'] for e in old + new if e['path'] not in snapshots[sha]['available_paths'])
        # A broken dependency must not look like successful removal of its flow.
        new_bad.update(renames.get(e['path'], e['path']) for e in old + new
                       if any(d.get('path') in new_bad for d in e.get('dependencies', [])))
        active = {renames.get(p, p): {**state, 'changes': list(state['changes'])}
                  for p, state in gap_states.get(parent, {}).items()}
        special_pairs = []
        handled = set(new_bad) | set(active)
        for bad_path in sorted(new_bad):
            previous_path = next((a for a, b in renames.items() if b == bad_path), bad_path)
            if bad_path not in active:
                base = [e for e in old if e['path'] == previous_path and previous_path not in old_bad]
                active[bad_path] = {'before_sha': parent, 'gap_start_sha': sha,
                                    'entities': base, 'changes': []}
                for entity in base:
                    special_pairs.append({'before': entity, 'after': None, 'match_status': 'gap_open',
                                          'change_kind': 'coverage_gap', 'gap_interval': {
                                              'last_observed_sha': parent, 'start_sha': sha, 'end_sha': None}})
            active[bad_path]['changes'].extend(changes)
        for restored_path in sorted(set(active) - new_bad):
            state = active.pop(restored_path)
            restored = [e for e in new if e['path'] == restored_path]
            prior_path = state['entities'][0]['path'] if state['entities'] else restored_path
            for pair in match_entities(state['entities'], restored, prior_path, restored_path):
                if pair['before'] is None:
                    continue  # no observed prior identity to restore
                special_pairs.append({**pair, 'change_kind': 'gap_resumed', 'gap_interval': {
                    'last_observed_sha': state['before_sha'], 'start_sha': state['gap_start_sha'], 'end_sha': sha},
                    'gap_changes': state['changes'] + changes})
        gap_states[sha] = active
        old_paths = {e['path'] for e in old}
        paired_new = set()
        pairs = []
        for old_path in sorted(old_paths):
            new_path = renames.get(old_path,old_path)
            paired_new.add(new_path)
            if new_path in handled or old_path in old_bad:
                continue
            pairs.extend(match_entities([e for e in old if e['path']==old_path],[e for e in new if e['path']==new_path],old_path,new_path))
        pairs.extend({'before':None,'after':e,'match_status':'unmatched','change_kind':'added'} for e in new if e['path'] not in paired_new and e['path'] not in handled)
        pairs = match_cross_file(pairs, {c['old_path'] for c in changes if c['old_path']},
                                 {c['new_path'] for c in changes if c['new_path']})
        candidate_pairs = []
        for pair in pairs:
            if pair['match_status'] != 'ambiguous' or pair['before'] is None:
                continue
            previous = pair['before']
            alternatives = [p['after'] for p in pairs if p['after'] and p['match_status'] == 'ambiguous'
                            and p['after']['symbol'] == previous['symbol']]
            candidate_pairs.extend({'before': previous, 'after': e} for e in alternatives + [None])
        selected_before, selected_after = set(), set()
        for index, override in enumerate(match_overrides or []):
            if override.get('repository_id') != rid or override.get('after_sha') != sha:
                continue
            if override.get('before_sha') != parent or parent not in snapshots:
                raise ValueError('Match override does not refer to the current verified parent snapshot')
            if override['before_key'] in selected_before or (override.get('after_key') is not None and override['after_key'] in selected_after):
                raise ValueError('Human match overrides must be one-to-one within a commit')
            chosen = resolve_match(snapshots[parent], snapshots[sha], override['before_key'],
                                   override.get('after_key'), candidate_pairs, override.get('reviewer', ''))
            selected_before.add(override['before_key'])
            if override.get('after_key') is not None:
                selected_after.add(override['after_key'])
            pairs = [p for p in pairs if not (p['before'] and entity_key(p['before']) == override['before_key'])
                     and not (p['after'] and entity_key(p['after']) == override.get('after_key'))]
            pairs.append({**chosen, 'machine_match_status': 'ambiguous'})
            applied_overrides.add(index)
        pairs.extend(special_pairs)
        for pair in pairs:
            before, after = pair['before'],pair['after']
            entity = after or before
            special = pair['change_kind'] in {'coverage_gap', 'gap_resumed'}
            if not special and behavior(before)==behavior(after) and (before or {}).get('path')==(after or {}).get('path'):
                continue
            related = []
            direct = False
            for change in pair.get('gap_changes', changes):
                for side,version,line_key,path_key in [('before',before,'deleted','old_path'),('after',after,'added','new_path')]:
                    if version is None:
                        continue
                    lines = {v[0] for v in change[line_key]}
                    if change[path_key]==version['path'] and (any(version['start_line']<=n<=version['end_line'] for n in lines) or change['old_path']!=change['new_path']):
                        direct = True
                        if change not in related:
                            related.append(change)
                    for dep in version.get('dependencies',[]):
                        if change[path_key]==dep['path'] and any(dep.get('start_line',0)<=n<=dep.get('end_line',10**9) for n in lines):
                            if change not in related:
                                related.append(change)
            if special and not related:
                related = pair.get('gap_changes', changes)
            if not related and not special:
                # A movement caused solely by unrelated inserted lines is not a
                # log edit. Unresolved AST matching remains auditable, not L2 proof.
                audit.append({'id':stable_id(rid,sha,entity['path'],entity['identity']),'repository_id':rid,'sha':sha,'path':entity['path'],'reason':'entity_change_without_intersecting_diff','status':'possible_related'})
                continue
            relation = pair['change_kind'] if special else 'direct_call_change' if direct else 'dependency_change'
            ev_id = stable_id(rid,parent,sha,(before or {}).get('path'),(after or {}).get('path'),entity['symbol'],entity['identity'],pair['change_kind'])
            event = {'id':ev_id,'log_change_id':ev_id,'repository_id':rid,'sha':sha,'parent_sha':parent,'topo_index':commit['topo_index'],'before':before,'after':after,'file_path':entity['path'],'symbol':entity['symbol'],'entity_fingerprint':stable_id(entity['path'],entity['symbol'],entity['identity']),'change_kind':pair['change_kind'],'behavior_match_status':pair['match_status'],'relation':relation,'diff_basis_sha':parent,'diff_target_sha':sha,'diff_backend':sorted({c['diff_backend'] for c in related}),'fallback_reason':sorted({c['fallback_reason'] for c in related if c['fallback_reason']}),'extraction_status':'ok' if all(c['extraction_status']=='ok' for c in related) else 'partial','file_change_ids':[c['change_id'] for c in related],'is_merge':commit['merge'],'on_target_first_parent':commit['on_target_first_parent'],'target_reachable':commit['target_reachable'],'parser_status':entity['parser_status'],'analysis_depth':1,'analysis_method':'bounded_static','tracked_dependencies':entity.get('dependencies',[])}
            if special:
                event.update(gap_interval=pair['gap_interval'], extraction_status='partial',
                             change_commit_attribution='interval_unknown',
                             comparison_before_sha=pair['gap_interval']['last_observed_sha'])
            if pair.get('match_review'):
                event.update(match_review=pair['match_review'], machine_match_status=pair['machine_match_status'])
            if pair['match_status'] == 'ambiguous':
                event['match_candidates'] = [{'before_key': entity_key(p['before']),
                    'after_key': entity_key(p['after']) if p['after'] else None,
                    'before_path': p['before']['path'], 'after_path': p['after']['path'] if p['after'] else None}
                    for p in candidate_pairs if
                    (before and entity_key(p['before']) == entity_key(before)) or
                    (after and p['after'] and entity_key(p['after']) == entity_key(after))]
            events.append(event)
        for change in changes:
            if not any(change['change_id'] in e['file_change_ids'] for e in events if e['sha']==sha):
                audit.append({'id':stable_id(rid,change['change_id'],'no_log_change'),'repository_id':rid,'sha':sha,'file_path':change['new_path'] or change['old_path'],'reason':'no_supported_log_behavior_change','file_change_id':change['change_id'],'manual_review_status':'pending'})
                if (change['new_path'] or change['old_path'] or '').endswith(('.yaml','.yml','.toml','.ini','.cfg','.conf','.json')):
                    gaps.append({'stage':'detect','repository_id':rid,'sha':sha,'path':change['new_path'] or change['old_path'],'error_type':'configuration_dependency_unresolved','reason':'Configuration changes retained; dynamic logger/filter effects are not statically resolved','retryable':False})
    unused = [i for i, item in enumerate(match_overrides or []) if item.get('repository_id') == rid and i not in applied_overrides]
    if unused:
        raise ValueError('Match overrides refer to unobserved or ineligible commits')
    return {'events':events,'snapshots':list(snapshots.values()),'gaps':gaps,'audit':audit}
