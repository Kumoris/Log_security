"""Bounded AIDev log sampling and reference-assisted type assessment (offline).

Run trace_aidev_reference_dfg.py first for actual PyDriller mining, sample here,
then semantic-dfg, then assess. Human case labels never become target field gold.
"""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import shutil

from agentlog_unified.config import now, sha256_file
from agentlog_unified.detector import detect_snapshot, LANGUAGES, PythonSnapshot
from agentlog_unified.export import write_csv, write_json, write_jsonl
from agentlog_unified.reference_library import apply_answers, records, verify_manifest
from agentlog_unified.semantic_context import HistoricalContext, load_run
from agentlog_unified.semantic_evidence import analyze_use, classify, digest, public_proof
from agentlog_unified.semantic_scan import stratified, use_sites
from agentlog_unified.storage import stable_id


def tables(output, items):
    for name, rows in items.items():
        write_jsonl(output/(name+'.jsonl'), rows)
        write_csv(output/(name+'.csv'), rows)


def start(output, inputs, options, resume, dry_run):
    if dry_run:
        return None, {'status':'dry_run','files_written':False,'network_calls':0}
    sources = Path(__file__).resolve().parents[1]/'src/agentlog_unified'
    fingerprint = {'inputs':{str(p.resolve()):sha256_file(p) for p in inputs},
                   'runner':sha256_file(Path(__file__)), 'options':options,
                   'implementation':{p.name:sha256_file(p) for p in sources.glob('*.py')}}
    if output.exists() and any(output.iterdir()):
        old = verify_manifest(output)
        if not resume or old['fingerprint']!=fingerprint:
            raise ValueError('changed_input_or_existing_output_use_new_directory')
        return fingerprint, {**json.loads((output/'coverage.json').read_text()),'resumed_without_reprocessing':True}
    return fingerprint, None


def finish(output, fingerprint, coverage):
    write_json(output/'coverage.json', coverage)
    write_json(output/'manifest.json', {'status':'complete','created_at':now(),'fingerprint':fingerprint,
        'artifact_sha256':{str(p.relative_to(output)):sha256_file(p) for p in output.rglob('*') if p.is_file()}})
    return coverage


def sample(seed, output, *, max_cases=100, resume=False, dry_run=False):
    seed, output = Path(seed), Path(output)
    if not 1<=max_cases<=100: raise ValueError('max_cases_must_be_1_to_100')
    fp, done = start(output,[seed/'manifest.json'],{'stage':'sample','max_cases':max_cases},resume,dry_run)
    if done: return done
    cases, snapshots, _ = load_run(seed)
    if len(cases)>max_cases: raise ValueError('budget_must_retain_all_seed_cases')
    paths = defaultdict(set)
    for c in cases.values():
        r=c['result'];paths[r['repository'],r['sha']].add(r['path'])
    frame={}; excluded=[]; gaps=[]; logs=0
    # All logs in the seed historical FILES, not a keyword-selected argument set.
    # ponytail: expand cached files only; broader repo sampling belongs upstream.
    for (repository,sha), selected_paths in sorted(paths.items()):
        raw=snapshots[repository,sha]
        files={p:raw['files'][p] for p in sorted(selected_paths)}
        # Wrapper detection needs the same dependency files as the seed miner.
        detected=detect_snapshot(raw['files'])
        entities=[e for e in detected['entities'] if e['path'] in selected_paths]
        logs+=len(entities); python_snapshot=PythonSnapshot(files)
        gaps += [dict(g,repository=repository,sha=sha) for g in detected['gaps']]
        for entity in entities:
            sites, omitted=use_sites(entity,files,python_snapshot=python_snapshot)
            excluded += [dict(g,repository=repository,sha=sha) for g in omitted]
            for site in sites:
                path=entity['path']; key=stable_id(repository,sha,path,entity['identity'],site)
                if not site.get('anchor'):
                    excluded.append({'id':key,'reason':'ast_use_anchor_unavailable'});continue
                row={'id':key,'repository':repository,'sha':sha,'path':path,'field':site['field'],
                     'scope':entity['symbol'],'language':LANGUAGES[Path(path).suffix],
                     'field_line':site['line'],'use_anchor':site['anchor'],'use_role':site['field_origin'],
                     'output_expression_anchor':site.get('output_expression_anchor'),
                     'ambiguity_source':'generic_name' if site['field'] in {'data','value','payload'} else 'other',
                     'fixture_or_tutorial_path':any(s in path.lower() for s in ('test','example','demo','debug_')),
                     'side':'snapshot','split':'development_pending_human',
                     'context':{'snapshot_gap_count':len(raw.get('gaps',[]))}}
                frame[key]={'id':key,'result':row,'source_versions':[{'path':path,'sha':sha,'source_sha256':digest(files[path])}],
                            'log_start_line':entity['start_line'],'log_end_line':entity['end_line'],
                            'log_statement_sha256':digest(entity['statement']), 'reference_ids':[],
                            'sampling_scope':'same_historical_file_log_not_proven_agent_modified'}
    for key, c in cases.items():
        if key not in frame: raise ValueError('seed_use_not_reproduced_in_sampling_frame')
        frame[key]['result']['side']=c['result']['side']
        frame[key]['history_event_id']=c.get('history_event_id')
        frame[key]['sampling_scope']='prior_AIDev_event_linked_use_requires_actor_review'
    additions=stratified([c['result'] for k,c in frame.items() if k not in cases],max_cases-len(cases),20260911)
    selected=set(cases)|{r['id'] for r in additions}
    for key in sorted(selected):
        c=frame[key];r=c['result'];ctx=HistoricalContext(c,snapshots[r['repository'],r['sha']])
        state=ctx.initial(24000)
        if state['status'] not in {'success','truncated'}:raise ValueError('sample_'+state['status'])
        c['supplementary_context']={'blocks':ctx.blocks,'missing':[{'reason':g.get('reason','snapshot_gap')} for g in ctx.snapshot.get('gaps',[])],
                                    'initial_status':state}
        c['log_statement_view']=next(b['code_view'] for b in ctx.blocks if b['kind']=='complete_log_statement')
        c['log_statement_is_verbatim']=False
        write_json(output/'evidence'/(key+'.json'),c)
    shutil.copy2(seed/'checkpoint.sqlite',output/'checkpoint.sqlite')
    tables(output, {'sampling_frame':[{**c['result'],'selected':k in selected,'sampling_scope':c['sampling_scope']} for k,c in frame.items()],
                    'not_selected':[{'id':k,'reason':'case_budget'} for k in frame if k not in selected],
                    'exclusions':excluded,'gaps':gaps,'seed_reference_links':records(seed/'reference_links.jsonl')})
    return finish(output,fp,{'status':'complete','seed_cases':len(cases),'selected_cases':len(selected),
        'additional_cases':len(selected)-len(cases),'frame_uses':len(frame),'historical_file_versions':sum(map(len,paths.values())),
        'log_statements':logs,'repositories':len({k[0] for k in paths}),'snapshots':len(paths),
        'selection':'retain_purposive_seed_then_stratify_all_log_uses_in_same_files_by_repo_language_generic_name',
        'seed_mining':json.loads((seed/'coverage.json').read_text()),'network_calls':0,'target_code_executed':False})


def reference_matches(types, index):
    """Alignment is a lookup after target assessment, never a semantic inference."""
    matches=[]
    for t in types:
        for ref in index:
            concept=bool(t.get('concept')) and t['concept']==ref.get('concept')
            pair=bool(t.get('category') and t.get('subtype')) and (t['category'],t['subtype'])==(ref.get('category'),ref.get('subtype'))
            if concept or pair:
                matches.append({'target_concept':t.get('concept'), 'reference_index_id':ref['id'],
                    'reference_case_id':ref.get('case_id'),'reference_id':ref.get('reference_id'),
                    'reference_concept':ref['concept'],'basis':'concept_alignment' if concept else 'catalog_pair_overlap',
                    'reference_origin':ref.get('origin'),'target_gold_inherited':False})
    return matches


def assess(run, dfg, library, output, *, adjudications=None, context_requests=None, resume=False, dry_run=False):
    run,dfg,library,output=map(Path,(run,dfg,library,output))
    inputs=[p/'manifest.json' for p in (run,dfg,library)]+[Path(p) for p in (adjudications,context_requests) if p]
    fp,done=start(output,inputs,{'stage':'assess'},resume,dry_run)
    if done:return done
    cases,snapshots,_=load_run(run); graph_manifest=verify_manifest(dfg);verify_manifest(library)
    if graph_manifest['fingerprint']['input_manifest']!=sha256_file(run/'manifest.json'):
        raise ValueError('dfg_belongs_to_another_frozen_run')
    requests=records(context_requests) if context_requests else []; retrievals=[]
    grouped=defaultdict(list)
    for req in requests:
        if req['case_id'] not in cases:raise ValueError('context_request_case_missing')
        grouped[req['case_id']].append(req)
    for key, group in grouped.items():
        c=cases[key];r=c['result'];ctx=HistoricalContext(c,snapshots[r['repository'],r['sha']])
        ctx.blocks=deepcopy(c['supplementary_context']['blocks'])
        for req in group:
            origin=req.get('origin_ref','').split(':')
            if len(origin)!=2 or origin[0]!='context' or not origin[1].isdigit() or int(origin[1])>=len(ctx.blocks):
                raise ValueError('invalid_context_origin_reference')
            query={**req,'origin_anchor':ctx.blocks[int(origin[1])]['id']}
            retrievals.append(ctx.retrieve(query,budget=24000,max_files=8))
        c['supplementary_context']['blocks']=ctx.blocks
        c['supplementary_context']['retrievals']=ctx.retrievals
    decisions=records(adjudications) if adjudications else []
    answers,guards=apply_answers(cases,decisions);by_id={r['id']:r for r in answers};decided={r['case_id'] for r in decisions}
    index=records(library/'type_index.jsonl'); rows=[]; reviews=[]; links=[]; types=[]; gap_rows=[]
    for key,c in sorted(cases.items()):
        r=c['result'];raw=snapshots[r['repository'],r['sha']];ctx=HistoricalContext(c,raw);ctx.initial(24000)
        analysis=analyze_use(raw['files'],r['repository'],r['sha'],r['path'],r['use_anchor'],max_chars=24000,max_hops=2)
        classification=classify(analysis);answer=deepcopy(by_id[key])
        relation=ctx.log_relation(); graph_path=dfg/'graphs'/(key+'.json')
        graph=json.loads(graph_path.read_text()) if graph_path.exists() else None
        if graph and any(graph[k]!=v for k,v in (('id',key),('repository',r['repository']),('sha',r['sha']),('path',r['path']))):
            raise ValueError('graph_use_identity_mismatch')
        if key not in decided:
            answer.update(semantic_status='supported' if analysis['review']['status']=='supported' else 'unknown',
                meaning=json.dumps(classification['meanings'],ensure_ascii=False) if classification['meanings'] else 'unknown: '+','.join(analysis['review']['reasons']),
                type_status='known' if classification['types'] else 'non_sensitive' if classification['queue']=='supported_non_sensitive' else 'unmapped' if classification['queue']=='known_semantics_unmapped' else 'unknown',
                sensitive_types=[{**t,'concept':t['subtype'],'sensitivity':'candidate'} for t in classification['types']],
                log_relation={'direct_original':'direct','selected_field':'direct','derived_count':'derived','derived_boolean':'derived','serialization_formatting':'serialized'}.get(relation['value'],'possible'),
                independent_semantic_review=analysis['review']['status'])
        gaps=sorted(set(analysis.get('gaps',[])+(graph['gaps'] if graph else ['dfg_missing'])+relation.get('gaps',[])))
        row={**answer,'language':r['language'],'use_anchor':r['use_anchor'],'sampling_scope':c['sampling_scope'],
             'fixture_or_tutorial_path':r['fixture_or_tutorial_path'],'ambiguity_source':r['ambiguity_source'],
             'dfg_log_relation':relation,'dfg_node_count':len(graph['nodes']) if graph else 0,
             'dfg_origin_counts':graph['origin_counts'] if graph else {},'gaps':gaps,
             'snapshot_has_gaps':bool(raw.get('gaps')),'runtime_confirmed':False,'model_stage':'not_run',
             'independent_rule_status':analysis['review']['status'], 'dfg_file':str(graph_path.resolve())}
        rows.append(row)
        reviews.append({'id':key,'candidate_origin':row['origin'],'rule_review':analysis['review'],
                        'assistant_candidate_semantically_verified_by_rule':False if key in decided else None,
                        'assistant_candidate_review':'pending_independent_semantic_review' if key in decided else 'not_applicable',
                        'name_only_hints':analysis.get('name_only_hints',[]),'classification':classification,
                        'proof':public_proof(analysis.get('proof'),raw['files']),'human_confirmed':False})
        for link in reference_matches(row['sensitive_types'],index):links.append(dict(link,id=stable_id(key,link),case_id=key))
        for t in row['sensitive_types']:
            types.append(dict(t,id=stable_id(key,t),case_id=key,repository=r['repository'],language=r['language'],
                              origin=row['origin'],log_relation=row['log_relation'],runtime_confirmed=False,human_confirmed=False))
        gap_rows.extend({'case_id':key,'reason':g} for g in gaps)
        write_json(output/'evidence'/(key+'.json'),c)
    summary=[]
    for concept in sorted({t['concept'] for t in types}):
        group=[t for t in types if t['concept']==concept]
        summary.append({'concept':concept,'field_uses':len({t['case_id'] for t in group}),
                        'repositories':sorted({t['repository'] for t in group}),'denominator':len(rows),
                        'origins':dict(Counter(t['origin'] for t in group)),'human_confirmed':False})
    coverage_rows=[]
    for dimension in ('repository','language','snapshot_has_gaps','sampling_scope','ambiguity_source'):
        for value in sorted({str(r[dimension]) for r in rows}):
            group=[r for r in rows if str(r[dimension])==value]
            coverage_rows.append({'dimension':dimension,'value':value,'denominator':len(group),
                'type_status':dict(Counter(r['type_status'] for r in group)),
                'types':dict(Counter(t['concept'] for r in group for t in r['sensitive_types'])),
                'human_labels':0,'accuracy':None})
    tables(output,{'field_types':rows,'type_occurrences':types,'type_summary':summary,'reference_links':links,
        'independent_reviews':reviews,'adjudication_guards':guards,'context_gaps':gap_rows,'context_retrievals':retrievals,
        'coverage_by_stratum':coverage_rows,
        'privacy_review_candidates':[r for r in rows if r['privacy_risk']=='static_candidate'],
        'conditional_carriers':[r for r in rows if any(t.get('sensitivity')=='conditional' for t in r['sensitive_types'])],
        'source_unknown':[r for r in rows if any(k in r['dfg_origin_counts'] for k in ('unknown','function_parameter','budget_boundary'))],
        'unknown_queue':[r for r in rows if r['type_status']=='unknown'],
        'unmapped_queue':[r for r in rows if r['type_status']=='unmapped'],
        'non_sensitive_controls':[r for r in rows if r['type_status']=='non_sensitive'],
        'human_review_queue':rows})
    return finish(output,fp,{'status':'complete_with_declared_gaps','field_uses':len(rows),
        'reference_records':len(records(library/'references.jsonl')),'reference_field_drafts':len(records(library/'field_answers.jsonl')),
        'semantics':dict(Counter(r['semantic_status'] for r in rows)), 'type_status':dict(Counter(r['type_status'] for r in rows)),
        'types':summary,'by_repository':dict(Counter(r['repository'] for r in rows)),
        'by_language':dict(Counter(r['language'] for r in rows)),
        'by_origin':dict(Counter(r['origin'] for r in rows)),
        'generic_name_cases':sum(r['ambiguity_source']=='generic_name' for r in rows),
        'fixture_or_tutorial_cases':sum(r['fixture_or_tutorial_path'] for r in rows),
        'cases_with_reference_alignment':len({l['case_id'] for l in links}),
        'cases_with_snapshot_gaps':sum(r['snapshot_has_gaps'] for r in rows),
        'independent_rule_status':dict(Counter(r['independent_rule_status'] for r in rows)),
        'human_field_labels':0,'evaluation_cases':0,'accuracy':None,'recall':None,
        'network_calls':0,'model_calls':0,'target_code_executed':False})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['sample','assess'])
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--dfg',type=Path);parser.add_argument('--references',type=Path)
    parser.add_argument('--adjudications',type=Path);parser.add_argument('--max-cases',type=int,default=100)
    parser.add_argument('--context-requests',type=Path,help='Anchored same-revision requests; no arbitrary paths')
    for flag in ('offline','dry-run','resume'):parser.add_argument('--'+flag,action='store_true')
    args=parser.parse_args()
    if args.stage=='sample':result=sample(args.input,args.output,max_cases=args.max_cases,resume=args.resume,dry_run=args.dry_run)
    else:
        if not args.dfg or not args.references:parser.error('assess requires --dfg and --references')
        result=assess(args.input,args.dfg,args.references,args.output,adjudications=args.adjudications,
                      context_requests=args.context_requests,resume=args.resume,dry_run=args.dry_run)
    print(json.dumps(result,ensure_ascii=False,indent=2))
