"""Frozen human case references and separately attributed field answers.

Benchmark fragments are not re-labelled as PyDriller historical files. Field
answers never inherit an enclosing issue/log's human sensitivity label.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit

from .config import now, sha256_file
from .export import write_csv, write_json, write_jsonl
from .issue_knowledge import load_knowledge
from .semantic_ast import Syntax, CALLS, STRINGS, walk, view
from .semantic_context import HistoricalContext, load_run
from .semantic_evidence import digest
from .semantic_review import blind_case, validate_reference
from .semantic_scan import use_sites
from .storage import stable_id, atomic_write, redact
from .taxonomy import taxonomy_catalog

VERSION = 'reference-library-1'
DEFECTS_SHA256 = 'e693da2c8492bae8ed95a7263def9a16ab44960f7488ab4dc64909d6b5eecaed'
DEFECTS_URL = 'https://github.com/klsc749/Defects4Log/blob/main/experiments/config_data/dataset.json'
PAPER_URL = 'https://arxiv.org/html/2508.11305v1'
ISSUE_ID = re.compile(r'\b[A-Z][A-Z0-9]+-\d+\b')


def records(path):
    return [json.loads(s) for s in Path(path).read_text().splitlines() if s.strip()]


def evidence_digest(case):
    return digest(json.dumps(redact(case), ensure_ascii=False, indent=2)+'\n')


def verify_manifest(folder, key='artifact_sha256'):
    folder = Path(folder)
    manifest = json.loads((folder/'manifest.json').read_text())
    for name, expected in manifest[key].items():
        p = Path(name)
        if p.is_absolute() or '..' in p.parts or not (folder/p).resolve().is_relative_to(folder.resolve()):
            raise ValueError('reference_manifest_path_outside_input')
        if sha256_file(folder/p) != expected:
            raise ValueError('reference_input_integrity_mismatch')
    return manifest


def norm(text):
    """Token spacing only: do not conflate whitespace inside string literals."""
    syntax = Syntax('fragment.java', text)
    def tokens(node):
        if node.type in STRINGS or not node.children:
            return [syntax.text(node)]
        return [t for child in node.children for t in tokens(child)]
    return [t for t in tokens(syntax.root) if t]


def target_call(source, target, path):
    syntax = Syntax(path, source)
    if syntax.root.has_error:
        raise ValueError('benchmark_java_parse_error')
    wanted = norm(target)
    matches = [n for n in syntax.nodes if n.type == 'method_invocation'
               and wanted[:len(norm(syntax.text(n)))+1] == norm(syntax.text(n))+[';']
               and syntax.text(n.child_by_field_name('name')) in {'trace','debug','info','warn','error','fatal'}]
    if len(matches) != 1:
        raise ValueError('benchmark_log_anchor_missing_or_ambiguous')
    return syntax, matches[0]


def sites_for_call(entity, source):
    sites, gaps = use_sites(entity, {entity['path']: source})
    # Object[] logging arguments need member expressions, not only the array
    # receiver. Reuse AST anchors; these are nested inputs, not separate sinks.
    syntax = Syntax(entity['path'], source)
    for site in list(sites):
        if site['field_origin'] != 'tree_sitter_log_argument':
            continue
        node = syntax.at(site['anchor'])
        if node is None:
            continue
        for member in walk(node):
            if member.type != 'array_initializer':
                continue
            for child in member.named_children:
                if child.type in STRINGS:
                    continue
                sites.append({'field': syntax.text(child), 'anchor': syntax.anchor(child),
                              'field_origin': 'array_log_element', 'line': child.start_point.row+1,
                              'output_expression_anchor': site['anchor']})
    # Prefer explicit array-element roles over generic nested identifiers.
    return list({stable_id(s['anchor']): s for s in sites}.values()), gaps


def make_case(repository, revision, path, source, entity, site, provenance, references, *, side='before'):
    anchor = site['anchor']
    syntax = Syntax(path, source); node = syntax.at(anchor)
    if node is None:
        raise ValueError('field_anchor_does_not_replay')
    function = syntax.function(node)
    scope = syntax.text(function.child_by_field_name('name')) if function else '<unknown>'
    expression = view(syntax.text(node), path)
    case_id = stable_id(VERSION, repository, revision, provenance.get('fix_commit_sha'), path, digest(source), anchor)
    # ponytail: bound public context to 24k chars; expand only cases with a recorded truncation.
    function_source = syntax.text(function) if function else source
    function_view = view(function_source, path)
    truncated = len(function_view) > 24000
    block = {'anchor': syntax.anchor(function) if function else anchor,
             'source_sha256': digest(source), 'snippet_sha256': digest(function_source),
             'code_view': function_view[:24000], 'truncated': truncated, 'is_verbatim': False}
    blocks = [block]
    outer = syntax.function(function) if function else None
    if outer:
        outer_source = syntax.text(outer); outer_view = view(outer_source, path)
        remaining = max(0, 24000-len(block['code_view']))
        blocks.append({'anchor':syntax.anchor(outer),'source_sha256':digest(source),
                       'snippet_sha256':digest(outer_source),'code_view':outer_view[:remaining],
                       'truncated':len(outer_view)>remaining,'is_verbatim':False})
        truncated = truncated or len(outer_view)>remaining
    missing = ['context_truncated'] if truncated else []
    if provenance.get('snapshot_gaps'):
        missing.append('historical_snapshot_has_recorded_gaps:'+str(len(provenance['snapshot_gaps'])))
    if provenance.get('source_backend')=='published_benchmark_code_fragment':
        missing += ['benchmark_parent_revision_not_supplied','complete_repository_context_not_in_fragment',
                    'upstream_graph_not_independently_validated']
    result = {'id': case_id, 'repository': repository, 'sha': revision, 'path': path,
              'scope': scope, 'language': 'java', 'field': expression, 'field_line': anchor['line'],
              'use_anchor': anchor, 'use_role': site['field_origin'], 'side': side,
              'output_expression_anchor': site.get('output_expression_anchor'),
              'split': 'development_reference', 'is_synthetic': False,
              'context': {'files': 1, 'max_chars': 24000,
                          'snapshot_gap_count':len(provenance.get('snapshot_gaps',[]))}}
    case = {'id': case_id, 'result': result, 'reference_ids': sorted(references),
            'source_provenance': provenance,
            'log_start_line': entity['start_line'], 'log_end_line': entity['end_line'],
            'log_statement_sha256': digest(entity['statement']),
            'log_statement_view': view(entity['statement'], path), 'log_statement_is_verbatim': False,
            'source_versions': [{'path': path, 'sha': revision, 'source_sha256': digest(source)}],
            'supplementary_context': {'blocks': blocks, 'missing': missing},
            'field_value_sha256': digest(syntax.text(node)),
            'human_field_confirmed': False, 'runtime_confirmed': False}
    return case


def group_references(references):
    """Connected source/issue/commit families; association is not deduplication."""
    parent = {r['id']: r['id'] for r in references}
    def root(x):
        while parent[x] != x:
            x = parent[x]
        return x
    seen = {}; links = []
    for r in references:
        keys = ['issue:'+x for x in r['issue_keys']]
        if r.get('commit_sha'):
            keys.append('commit:'+r['commit_sha'])
        for key in keys:
            if key in seen:
                other = seen[key]; parent[root(r['id'])] = root(other)
                links.append({'id': stable_id(r['id'], other, key), 'left': other, 'right': r['id'],
                              'basis': key, 'relation': 'same_or_related_case_family_not_independent'})
            else:
                seen[key] = r['id']
    members = defaultdict(list)
    for r in references:
        members[root(r['id'])].append(r['id'])
    for r in references:
        r['split_group'] = stable_id('reference_family', sorted(members[root(r['id'])]))
        r['split'] = 'development_reference'
    return links


def unknown_answer(case):
    r = case['result']
    return {'id': case['id'], 'case_id': case['id'], 'reference_ids': case['reference_ids'],
            'field': r['field'], 'repository': r['repository'], 'path': r['path'], 'sha': r['sha'],
            'side': r['side'], 'scope': r['scope'], 'semantic_status': 'unknown',
            'meaning': '已定位该日志参数使用位置；尚无经过逐字段裁决的业务含义。',
            'type_status': 'unknown', 'sensitive_types': [], 'evidence_refs': ['use','log','context:0'],
            'log_relation': 'direct' if r['use_role']=='tree_sitter_log_argument' else 'possible',
            'privacy_risk': 'undetermined', 'origin': 'rule_structural_extraction',
            'human_confirmed': False, 'human_review_status': 'pending_human_review',
            'runtime_confirmed': False, 'semantic_gold_eligible': False,
            'metadata_semantics': 'dataset provenance is separate from target program variables',
            'independent_semantic_review': 'not_run', 'model': None, 'prompt_version': None,
            'meaning_scope': 'bounded_program_role_not_complete_business_schema',
            'status': 'pending_field_adjudication'}


def apply_answers(cases, decisions):
    if len({r['case_id'] for r in decisions}) != len(decisions):
        raise ValueError('duplicate_field_adjudication')
    by_id = {r['case_id']: r for r in decisions}; answers = []; checks = []
    if set(by_id)-set(cases):
        raise ValueError('field_adjudication_case_missing')
    for key, case in sorted(cases.items()):
        answer = unknown_answer(case); decision = by_id.get(key)
        if decision:
            if decision.get('origin') != 'assistant_source_adjudication' or decision.get('human_confirmed') is not False:
                raise ValueError('field_decision_must_not_impersonate_human')
            if decision.get('evidence_sha256') != evidence_digest(case):
                raise ValueError('field_adjudication_evidence_changed')
            validate_reference(deepcopy(decision), case)
            evidence = {r['id']: r for r in blind_case(case)['evidence']}
            guards = decision.get('evidence_guards', [])
            if decision['semantic_status']=='supported' and not guards:
                raise ValueError('supported_field_answer_requires_context_guard')
            for guard in guards:
                if not guard.get('contains') or guard.get('ref') not in decision['evidence_refs'] or guard['contains'] not in (evidence.get(guard['ref'],{}).get('code_view') or ''):
                    raise ValueError('field_answer_context_guard_failed')
            catalog={(c['category'],t['subtype']) for c in taxonomy_catalog()['categories'] for t in c['subtypes']}
            for t in decision['sensitive_types']:
                if t.get('subtype') is not None and (t.get('category'),t['subtype']) not in catalog:
                    raise ValueError('field_answer_unknown_catalog_mapping')
            answer.update({k: decision[k] for k in ('semantic_status','meaning','type_status','sensitive_types',
                                                   'log_relation','privacy_risk','evidence_refs','origin')})
            answer.update(status='assistant_field_answer_pending_human',
                          rationale=decision.get('rationale',''), independent_semantic_review='pending_human_or_independent_model')
            answer['evidence_guards']=guards
        checks.append({'id': key, 'status': 'supported', 'method': 'anchor_hash_and_reference_schema_replay',
                       'semantic_correctness_verified': False, 'human_confirmed': False,
                       'checks': ['original_use_anchor_replayed','source_snippet_hash_retained',
                                  'log_anchor_replayed','separate_label_scope'] + (['decision_evidence_digest_matches','evidence_refs_resolve'] if decision else [])})
        answer['evidence_sha256'] = evidence_digest(case)
        answers.append(answer)
    return answers, checks


def build_library(input_path, output, *, offline=True, dry_run=False, resume=False):
    if not offline:
        raise ValueError('reference_library_uses_local_frozen_evidence_only')
    input_path, output = Path(input_path).resolve(), Path(output).resolve()
    spec = json.loads(input_path.read_text())
    def path(key):
        p = Path(spec[key]); return p.resolve() if p.is_absolute() else (input_path.parent/p).resolve()
    knowledge, issues_path, dataset = path('issue_knowledge'), path('issue_answers'), path('defects_dataset')
    if sha256_file(dataset) != DEFECTS_SHA256:
        raise ValueError('defects4log_release_digest_mismatch_no_human_provenance_inheritance')
    human = load_knowledge(knowledge)
    verify_manifest(issues_path.parent, 'files')
    issues = records(issues_path); old = {r['id']: r for r in human}
    if len(human)!=67 or len(issues)!=67 or {r['source_annotation_id'] for r in issues}!=set(old):
        raise ValueError('human67_source_identity_mismatch')
    inputs = {input_path, dataset, knowledge/'manifest.json', issues_path, issues_path.parent/'manifest.json'}
    references = []
    for row in issues:
        annotation = old[row['source_annotation_id']]['human_annotation']
        if annotation['origin']!='human' or annotation['label']!='sensitive_information':
            raise ValueError('human67_sensitive_label_missing')
        references.append({'id': 'issue:'+row['issue'], 'source_set': 'human67', 'source_id': row['source_annotation_id'],
            'issue_keys': [row['issue']], 'source_url': row['issue_url'], 'human_annotation': annotation,
            'label_scope': 'issue_group_sensitivity', 'label': 'sensitive_information',
            'concepts': row['concepts'], 'concept_origin': row['review_origin'],
            'reference_type_status': row['type_status'],
            'source_answer_zh': row['reference_answer_zh'], 'source_evidence': row['evidence'],
            'application_log_relation': row['application_log_relation'], 'field_gold_inherited': False})
    all_defects = json.loads(dataset.read_text()); defects = []
    for offset, row in enumerate(all_defects):
        if row['label']!='Sensitive Information Exposure':
            continue
        meta = row['meta_info']; repository = '/'.join(urlsplit(meta['url']).path.split('/')[1:3])
        ref = {'id': 'defects4log:'+str(row['index']), 'source_set': 'defects4log23', 'source_id': row['index'],
            'issue_keys': sorted(set(ISSUE_ID.findall(meta['message']))), 'source_url': meta['url'],
            'repository': repository, 'commit_sha': meta['sha'], 'path': meta['file_path'],
            'reported_log_lines': meta['line_nums'], 'label': row['label'],
            'label_scope': 'target_logging_defect_pattern', 'concepts': [],
            'human_annotation': {'origin':'human','annotator':'Defects4Log study authors',
                'basis':'published_manually_curated_developer_verified_benchmark', 'paper':PAPER_URL,
                'subtype_confirmed':False,'local_human_reannotation':False},
            'source_provenance': {'dataset_url':DEFECTS_URL, 'dataset_sha256':DEFECTS_SHA256,
                'json_pointer':'/'+str(offset), 'code_sha256':digest(row['code']),
                'fixed_code_sha256':digest(row['fixed_code'])}, 'field_gold_inherited':False}
        references.append(ref); defects.append((ref,row,offset))
    if len(defects)!=23:
        raise ValueError('defects4log_sensitive_count_mismatch')
    pairs = []
    for name in spec.get('code_pairs', []):
        p = (input_path.parent/name).resolve(); verify_manifest(p.parent)
        inputs.update((p,p.parent/'manifest.json'))
        pairs.extend(r for r in records(p) if r.get('commit_sha') and r.get('status') in {'code_pair_extracted','partial_code_pair'})
    pair_map = {(r['repository'],r['commit_sha']): r for r in pairs}
    for ref in references:
        matched = [p for p in pairs if 'issue:'+p['id']==ref['id']]
        if matched:
            ref.update(repository=matched[0]['repository'], commit_sha=matched[0]['commit_sha'],
                       historical_code_pair_available=True)
    loaded = []
    for name in spec.get('semantic_runs', []):
        p = (input_path.parent/name).resolve(); _, snapshots, _ = load_run(p)
        inputs.update((p/'manifest.json',p/'checkpoint.sqlite'))
        with sqlite3.connect(f'file:{p}/checkpoint.sqlite?mode=ro',uri=True) as db:
            units = [json.loads(r[0]) for r in db.execute("SELECT data FROM records WHERE kind='mined_units'")]
        loaded.append((p,snapshots,units))
    decision_path = path('field_adjudications') if spec.get('field_adjudications') else None
    if decision_path: inputs.add(decision_path)
    fingerprint = {'version':VERSION,'inputs':{str(p):sha256_file(p) for p in sorted(inputs)},
                   'implementation': {p.name:sha256_file(p) for p in Path(__file__).parent.glob('*.py')}}
    if dry_run:
        return {'status':'dry_run','exit_code':0,'references':len(references),'files_written':False,'network_calls':0}
    if output.exists() and any(output.iterdir()):
        if not resume or not (output/'manifest.json').exists():
            raise ValueError('reference_output_requires_new_directory_or_resume')
        previous = verify_manifest(output)
        if previous['fingerprint'] != fingerprint:
            raise ValueError('reference_inputs_changed_use_new_output')
        return {**json.loads((output/'coverage.json').read_text()),'resumed_without_scan':True}
    if any(p==output or p.is_relative_to(output) for p in inputs):
        raise ValueError('output_contains_reference_input')
    cases = {}; gaps = []; site_exclusions = []; log_locations = {}
    def record_omissions(omitted, **identity):
        for item in omitted:
            destination=site_exclusions if item['reason']=='fixed_log_message_template' else gaps
            destination.append({**identity,**item})
    for ref,row,offset in defects:
        path_name=ref['path']; source=row['code']
        syntax, call = target_call(source,row['target_logging_statement'],path_name)
        log_key=stable_id(ref['repository'],ref['commit_sha'],path_name,digest(source),syntax.anchor(call))
        if log_key in log_locations:
            ref['duplicate_of']=log_locations[log_key]
            for case in cases.values():
                if ref['duplicate_of'] in case['reference_ids']:
                    case['reference_ids'].append(ref['id']);case['reference_ids'].sort()
            continue
        log_locations[log_key]=ref['id']
        entity={'path':path_name,'statement':syntax.text(call),'start_line':call.start_point.row+1,'end_line':call.end_point.row+1}
        sites,omitted=sites_for_call(entity,source)
        record_omissions(omitted,reference_id=ref['id'])
        for site in sites:
            provenance={**ref['source_provenance'],'source_file':str(dataset),'code_pointer':'/'+str(offset)+'/code',
                'fix_commit_sha':ref['commit_sha'],'before_revision_sha':None,'source_backend':'published_benchmark_code_fragment',
                'history_reverified':False,'fallback_reason':'benchmark_parent_revision_not_supplied',
                'coordinate_system':'UTF8 bytes and lines within dataset code fragment; reported lines kept separately',
                'reported_log_lines':ref['reported_log_lines'],'upstream_graph_status':'machine_context_not_human_flow_truth'}
            case=make_case(ref['repository'],None,path_name,source,entity,site,provenance,[ref['id']])
            case['fixed_code_view']=view(row['fixed_code'],path_name)
            case['fixed_code_sha256']=digest(row['fixed_code'])
            cases[case['id']]=case
    for run,snapshots,units in loaded:
        for unit in units:
            for event in unit['events']:
                pair=pair_map.get((unit['repository'],event['sha']))
                if not pair or 'issue:'+pair['id'] not in {r['id'] for r in references}:
                    gaps.append({'reason':'historical_event_reference_link_missing','event_id':event['id']});continue
                ref_id='issue:'+pair['id']
                for side,revision in [('before',event['parent_sha']),('after',event['sha'])]:
                    entity=event.get(side)
                    if not entity:continue
                    snapshot=snapshots.get((unit['repository'],revision));source=(snapshot or {}).get('files',{}).get(entity['path'])
                    if source is None:
                        gaps.append({'reference_id':ref_id,'reason':'historical_source_missing','side':side});continue
                    sites,omitted=sites_for_call(entity,source)
                    record_omissions(omitted,reference_id=ref_id,side=side)
                    for site in sites:
                        if not site.get('anchor'):
                            gaps.append({'reference_id':ref_id,'reason':'field_anchor_missing'});continue
                        provenance={'source_run':str(run),'source_backend':'reused_verified_pydriller_checkpoint',
                            'file_provenance':snapshot.get('file_provenance',{}).get(entity['path']),
                            'snapshot_backend':snapshot.get('backend'),'fallback_reason':snapshot.get('fallback_reason'),
                            'diff_backend':event['diff_backend'],'diff_fallback_reason':event['fallback_reason'],
                            'snapshot_gaps':snapshot.get('gaps',[]),'event_id':event['id'],
                            'parent_sha':event['parent_sha'],'commit_sha':event['sha'],
                            'source_checkpoint_sha256':sha256_file(run/'checkpoint.sqlite'),
                            'coordinate_system':'historical file UTF8 byte offsets and original lines'}
                        case=make_case(unit['repository'],revision,entity['path'],source,entity,site,provenance,[ref_id],side=side)
                        # Independent replay also validates source version and exact full log hash.
                        context=HistoricalContext(case,snapshot)
                        if context.initial()['status'] not in {'success','truncated'}:
                            raise ValueError('historical_log_context_replay_failed')
                        cases[case['id']]=case
    links=group_references(references)
    refs_by_id={r['id']:r for r in references}
    for case in cases.values():
        case['split_groups']=sorted({refs_by_id[r]['split_group'] for r in case['reference_ids']})
    decisions=records(decision_path) if decision_path else []
    answers,checks=apply_answers(cases,decisions)
    covered={r for c in cases.values() for r in c['reference_ids']}
    for ref in references:
        ref['field_case_ids']=sorted(k for k,c in cases.items() if ref['id'] in c['reference_ids'])
        if ref['id'] not in covered:
            gaps.append({'reference_id':ref['id'],'reason':('code_pair_available_no_linked_log_field' if ref.get('historical_code_pair_available')
                                                          else 'historical_code_pair_not_in_reused_inputs'),
                         'original_human_label_retained':True})
        write_json(output/'references'/(stable_id(ref['id'])+'.json'),ref)
    for key,case in cases.items():
        write_json(output/'evidence'/(key+'.json'),case)
    queue=[{'id':r['id'],'case_id':r['id'],'reason':'field_human_review_pending',
            'semantic_status':r['semantic_status'],'type_status':r['type_status']} for r in answers]
    types=[{'id':stable_id(r['id'],c),'reference_id':r['id'],'concept':c,'origin':r.get('concept_origin'),
            'scope':'issue_context_concept_not_field_gold'} for r in references for c in r['concepts']]
    types += [{'id':stable_id(r['id'],t),'case_id':r['id'],**t,'origin':r['origin'],
               'scope':'exact_field_use_pending_human'} for r in answers for t in r['sensitive_types']]
    excluded=[{'id':'defects4log:'+str(r['index']),'original_label':r['label'],
               'reason':'other_logging_defect_not_a_sensitive_positive','non_sensitive_gold':False}
              for r in all_defects if r['label']!='Sensitive Information Exposure']
    tables={'references':references,'field_answers':answers,'evidence_checks':checks,'case_links':links,
            'type_index':types,'review_queue':queue,'coverage_gaps':gaps,'other_defects':excluded,
            'field_exclusions':site_exclusions,
            'reference_type_review_queue':[r for r in references if r.get('reference_type_status')=='specific_sensitive_type_not_established'],
            'semantic_unknown':[r for r in answers if r['semantic_status']=='unknown'],
            'unmapped_types':[r for r in answers if r['type_status']=='unmapped'],
            'type_unknown':[r for r in answers if r['type_status']=='unknown']}
    tables['type_summary']=[{'concept':concept,'scope':scope,'field_or_reference_entries':count}
                           for (concept,scope),count in sorted(Counter((r['concept'],r['scope']) for r in types).items())]
    for name,rows in tables.items():
        write_jsonl(output/(name+'.jsonl'),rows);write_csv(output/(name+'.csv'),rows)
    report={'status':'complete','exit_code':0,'reference_records':len(references),
        'human67_records':len(human),'defects4log_sensitive_records':len(defects),
        'related_case_groups':len({r['split_group'] for r in references}),
        'duplicate_log_records':sum('duplicate_of' in r for r in references),
        'references_with_fields':len(covered),'human67_with_fields':sum(r.startswith('issue:') for r in covered),
        'defects4log_with_fields':sum(r.startswith('defects4log:') for r in covered),
        'field_use_instances':len(cases),'assistant_field_answers':len(decisions),'human_field_answers':0,
        'field_semantic_status':dict(Counter(r['semantic_status'] for r in answers)),
        'field_type_status':dict(Counter(r['type_status'] for r in answers)),
        'fields_by_repository':dict(Counter(r['repository'] for r in answers)),
        'fields_by_source':dict(Counter(c['source_provenance']['source_backend'] for c in cases.values())),
        'fields_by_language':dict(Counter(c['result']['language'] for c in cases.values())),
        'references_without_fields':len(references)-len(covered),
        'source_issue_concepts':len({c for r in references for c in r['concepts']}),
        'field_type_concepts':len({t['concept'] for a in answers for t in a['sensitive_types']}),
        'gap_reasons':dict(Counter(g['reason'] for g in gaps)),
        'excluded_static_templates':len(site_exclusions),
        'coverage_gap_records':len(gaps),'other_defect_records':len(excluded),'evaluation_cases':0,
        'network_calls':0,'model_calls':0,'target_code_executed':False,'accuracy':None,'recall':None,
        'history_policy':'published_fragments_or_verified_PyDriller_cache; no latest source substitution'}
    write_json(output/'coverage.json',report)
    write_csv(output/'funnel.csv',[{'stage':k,'count':report[k]} for k in ('reference_records','human67_records',
        'defects4log_sensitive_records','references_with_fields','field_use_instances','assistant_field_answers','human_field_answers')])
    guide=['# 人工敏感性与日志隐私缺陷参考库',
        '67 组人工敏感性参考与 23 条 Defects4Log 标签分别保留；字段答案有独立来源，不继承人工作者确认。',
        '本版均为开发参考，不含独立评估集。关联 issue、同一提交及重复日志按 split_group 保持同组；未来拆分还应按仓库隔离。',
        '[来源记录](references.csv) · [字段答案](field_answers.csv) · [类型索引](type_index.csv) · [缺失队列](coverage_gaps.csv)',
        'Defects4Log 的 code/fixed_code 是发布片段，行号与字节锚点属于片段；修复提交不充当修改前版本。原报告行号另存。',
        '已有 issue 历史复用带哈希校验的 PyDriller checkpoint；上下文缺失与未解析数据流保留。',
        '标准参考适用范围：人工 issue 敏感性、原论文日志缺陷标签。新增字段解释是助手裁决草案，待独立人工标注。',
        '## 字段答案', '| ID / 来源 | 字段 | 含义 | 语义 / 类型 |', '|---|---|---|---|']
    for a in answers:
        clean=lambda s:str(s).replace('|','\\|').replace('\n',' ')
        guide.append('| ['+a['id'][:12]+'](evidence/'+a['id']+'.json) / '+', '.join(a['reference_ids'])+' | '+
                     clean(a['field'])+' | '+clean(a['meaning'])+' | '+a['semantic_status']+' / '+a['type_status']+' |')
    atomic_write(output/'README.md','\n\n'.join(guide[:8])+'\n'+'\n'.join(guide[8:])+'\n')
    write_json(output/'manifest.json',{'status':'complete','created_at':now(),'fingerprint':fingerprint,
        'artifact_sha256':{str(p.relative_to(output)):sha256_file(p) for p in output.rglob('*') if p.is_file()}})
    return report
