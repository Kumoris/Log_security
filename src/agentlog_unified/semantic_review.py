"""Append-only human coding and codebook decisions over frozen semantic packs."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .config import now, sha256_file
from .export import write_csv, write_json, write_jsonl
from .storage import Store, stable_id


def blind_case(case):
    """Allowlist historical observations; exclude proposals, verdicts and labels."""
    result=case['result']
    identity={k:result.get(k) for k in ('id','repository','sha','path','scope','language','field','use_anchor','field_line','use_role','output_expression_anchor','split','is_synthetic')}
    refs=[]
    if result.get('use_anchor'):
        refs.append({'id':'use','anchor':result['use_anchor'],'sha':result.get('sha')})
    if case.get('log_statement_sha256'):
        refs.append({'id':'log','path':result.get('path'),'sha':result.get('sha'),
                     'start_line':case.get('log_start_line'),'end_line':case.get('log_end_line'),
                     'snippet_sha256':case['log_statement_sha256'],'code_view':case.get('log_statement_view'),
                     'is_verbatim':case.get('log_statement_is_verbatim',False)})
    for i,block in enumerate(case.get('supplementary_context',{}).get('blocks',[])):
        refs.append({'id':'context:'+str(i),**{k:block.get(k) for k in ('anchor','source_sha256','snippet_sha256','code_view','truncated','is_verbatim')}})
    for i,source in enumerate(case.get('source_versions',[])):
        refs.append({'id':'source:'+str(i),**{k:source.get(k) for k in ('path','sha','source_sha256')}})
    return {'id':case.get('id',result.get('id')),'identity':identity,'evidence':refs,
            'source_coordinates':{k:v for k,v in case.get('source_provenance',{}).items() if k in
                ('source_backend','coordinate_system','reported_log_lines','before_revision_sha')},
            'missing_context':case.get('supplementary_context',{}).get('missing',[]),
            'context_availability':{k:result.get('context',{}).get(k) for k in ('files','max_chars','snapshot_gap_count')},
            'machine_answers_included':False,'raw_values_reconstructed':False}


def validate_reference(row, case):
    if row.get('status')!='submitted' or not row.get('meaning','').strip():
        raise ValueError('reference requires submitted status and an explicit meaning or unknown reason')
    choices={'semantic_status':{'supported','unknown','conflict'},
             'type_status':{'known','unmapped','unknown','non_sensitive','conflict'},
             'log_relation':{'direct','serialized','derived','possible','not_observed','unknown'},
             'privacy_risk':{'static_candidate','no_evidence','undetermined','not_applicable'}}
    for key,values in choices.items():
        if row.get(key) not in values:raise ValueError('reference dimension invalid: '+key)
    for key in ('sensitive_types','evidence_refs'):
        if isinstance(row.get(key),str):row[key]=json.loads(row[key])
        if not isinstance(row.get(key),list):raise ValueError('reference list required: '+key)
    if any(not isinstance(t,dict) or not t.get('concept') for t in row['sensitive_types']):
        raise ValueError('reference types require explicit concepts; taxonomy mapping is optional')
    if row['type_status'] in {'known','unmapped'} and not row['sensitive_types']:
        raise ValueError('known/unmapped reference requires a concept')
    if row['type_status'] in {'unknown','non_sensitive'} and row['sensitive_types']:
        raise ValueError('unknown/non_sensitive reference must not assert sensitive types')
    valid={r['id'] for r in blind_case(case)['evidence']}
    if not row['evidence_refs'] or any(not isinstance(ref,str) or ref not in valid for ref in row['evidence_refs']):
        raise ValueError('reference evidence does not resolve in the blind case')


def coding(run,output,*,file=None,reviewer=None,dry_run=False,resume=False):
    run=Path(run);output=Path(output)
    if dry_run:return {'status':'dry_run','files_written':False,'exit_code':0}
    if output.exists() and any(output.iterdir()) and not resume:raise ValueError('existing coding ledger requires --resume')
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest['status']!='complete':raise ValueError('human coding needs a completed frozen semantic run')
    for relative,expected in manifest['artifact_sha256'].items():
        if sha256_file(run/relative)!=expected:raise ValueError('semantic evidence integrity mismatch')
    cases={p.stem:json.loads(p.read_text()) for p in (run/'evidence').glob('*.json')}
    fingerprint=sha256_file(run/'manifest.json');rows=[]
    if (output/'coding_audit.json').exists() and json.loads((output/'coding_audit.json').read_text())['run_manifest_sha256']!=fingerprint:
        raise ValueError('coding ledger belongs to another frozen run')
    if file:
        if not reviewer or not reviewer.strip():raise ValueError('a self-declared human reviewer identity is required')
        source=Path(file)
        rows=list(csv.DictReader(source.open(newline='',encoding='utf-8-sig'))) if source.suffix=='.csv' else [json.loads(line) for line in source.read_text().splitlines() if line.strip()]
    accepted=[]
    for row in rows:
        if row.get('status') in {'pending','pending_human_review',''}:continue
        if row.get('origin')!='human' or row.get('model') or row.get('human_confirmed') is False:
            raise ValueError('only explicitly human-origin records enter the human ledger')
        kind=row.get('kind','annotation')
        ids=row.get('case_ids') or [row.get('case_id')]
        if isinstance(ids,str):ids=json.loads(ids)
        if not ids or any(i not in cases for i in ids):raise ValueError('coding record refers to unknown evidence')
        if kind in {'annotation','reference_annotation'}:
            if len(ids)!=1:raise ValueError('one case per annotation is required')
            if row.get('status')!='submitted':raise ValueError('annotation status must be submitted')
            if kind=='annotation':
                for dimension in ('semantic_correct','type_correct','log_link_correct','privacy_risk_correct'):
                    if row.get(dimension) not in {'correct','incorrect','unknown','not_applicable'}:
                        raise ValueError('all four independent coding dimensions are required')
            else:validate_reference(row,cases[ids[0]])
            if row.get('evidence_sha256')!=sha256_file(run/'evidence'/(ids[0]+'.json')):
                raise ValueError('annotation evidence changed or its digest was omitted')
        elif kind in {'category_proposal','category_decision'}:
            if any(cases[i]['result']['split']=='evaluation_pending_human' for i in ids):
                raise ValueError('category development must not consume held-out evaluation cases')
            if row.get('action') not in {'new','split','merge','rename','map'} or not row.get('rationale') or not row.get('categories'):
                raise ValueError('category change requires an action, categories and rationale')
            if kind=='category_decision' and (row.get('status') not in {'accepted','rejected','deferred'} or not row.get('proposal_id')):
                raise ValueError('human decision must identify a proposal and disposition')
        else:raise ValueError('unknown coding record kind')
        accepted.append({**row,'kind':kind,'case_ids':ids,'reviewer':reviewer.strip(),'origin':'human',
                         'identity_verification':'self_declared_not_authenticated','run_manifest_sha256':fingerprint})
    db=Store(output/'coding.sqlite')
    try:
        prior=db.rows('coding_history')
        if prior and any(r['run_manifest_sha256']!=fingerprint for r in prior):raise ValueError('coding ledger belongs to another frozen run')
        known={r['id']:r for r in prior}
        staged=[]
        for row in accepted:
            row['id']=stable_id(row)
            if row['kind']=='category_decision':
                proposal=known.get(row['proposal_id'])
                if not proposal or proposal['kind']!='category_proposal':raise ValueError('category proposal must already exist')
                if any(row.get(k)!=proposal.get(k) for k in ('action','categories','case_ids')):raise ValueError('decision changes the proposed category operation')
            if row['id'] not in known:
                row['recorded_at']=now();staged.append(row);known[row['id']]=row
        # Validate everything before committing any imported decision.
        with db.db:
            for row in staged:db.db.execute('INSERT INTO records VALUES(?,?,?)',('coding_history',row['id'],json.dumps(row)))
        history=db.rows('coding_history');latest={};decisions={};references={}
        for row in sorted(history,key=lambda r:(r['recorded_at'],r['id'])):
            if row['kind']=='annotation':latest[(row['case_ids'][0],row['reviewer'])]=row
            if row['kind']=='reference_annotation':references[(row['case_ids'][0],row['reviewer'])]=row
            if row['kind']=='category_decision':decisions[row['proposal_id']]=row
        disagreements=[]
        for case_id in cases:
            coded=[r for (i,_),r in latest.items() if i==case_id]
            if len({tuple(r[d] for d in ('semantic_correct','type_correct','log_link_correct','privacy_risk_correct')) for r in coded})>1:
                disagreements.append({'case_id':case_id,'status':'pending_human_adjudication','annotation_ids':[r['id'] for r in coded]})
            field_refs=[r for (i,_),r in references.items() if i==case_id]
            dimensions=('semantic_status','meaning','type_status','sensitive_types','log_relation','privacy_risk')
            if len({json.dumps({d:r[d] for d in dimensions},sort_keys=True) for r in field_refs})>1:
                disagreements.append({'case_id':case_id,'kind':'reference_annotation',
                    'status':'pending_human_adjudication','annotation_ids':[r['id'] for r in field_refs]})
        template=[{'case_id':i,'evidence_sha256':sha256_file(run/'evidence'/(i+'.json')),
                   'split':case['result']['split'],'origin':'human','kind':'annotation','status':'pending_human_review',
                   'semantic_correct':'','type_correct':'','log_link_correct':'','privacy_risk_correct':'',
                   'meaning':'','category':'','subtype':'','evidence_refs':'','notes':''} for i,case in cases.items()]
        reference_template=[{'case_id':i,'evidence_sha256':sha256_file(run/'evidence'/(i+'.json')),
            'split':case['result']['split'],'origin':'human','kind':'reference_annotation','status':'pending_human_review',
            'semantic_status':'','meaning':'','type_status':'','sensitive_types':[],
            'log_relation':'','privacy_risk':'','evidence_refs':[],'notes':''} for i,case in cases.items()]
        for i,case in cases.items():write_json(output/'blind_evidence'/(i+'.json'),blind_case(case))
        guide=['# 字段参考答案：独立人工标注',
            '本文件只展示历史证据。请另存 reference_template.csv 或 JSONL 后填写；保留 case_id 与 evidence_sha256。',
            '分别填写含义、敏感类型、日志关联、隐私风险。上下文不足时写 unknown 及原因；不存在真实值不代表非敏感。',
            'semantic_status：supported / unknown / conflict；type_status：known / unmapped / unknown / non_sensitive / conflict。',
            'log_relation：direct / serialized / derived / possible / not_observed / unknown；privacy_risk：static_candidate / no_evidence / undetermined / not_applicable。',
            'sensitive_types 填 JSON 数组，元素包含 concept，可另填 category、subtype；未知或非敏感填 []。evidence_refs 填下方证据编号的 JSON 数组。',
            '完成的行设 status=submitted；未审行保留 pending_human_review。原始字符串已隐藏，不应推测或还原真实凭证。',
            'Java 等 AST 视图保留行序；Python 视图经过格式化。所有列号与行锚点指向原始历史源码。']
        for i,case in sorted(cases.items()):
            blind=blind_case(case);identity=blind['identity']
            guide += ['## '+i, str(identity.get('repository'))+' · '+str(identity.get('sha')),
                      '`'+str(identity.get('path'))+'` · 字段 `'+str(identity.get('field'))+'` · 行 '+str(identity.get('field_line')),
                      '[结构化证据](blind_evidence/'+i+'.json)']
            for ref in blind['evidence']:
                if not ref.get('code_view'):continue
                guide += ['证据 `'+ref['id']+'` · '+json.dumps(ref.get('anchor') or {'start_line':ref.get('start_line'),'end_line':ref.get('end_line')},ensure_ascii=False),
                          '```\n'+ref['code_view']+'\n```']
            guide += ['上下文可用性：'+json.dumps(blind['context_availability'],ensure_ascii=False)]
        (output/'blind-review.md').write_text('\n\n'.join(guide)+'\n',encoding='utf-8')
        for name,records in {'coding_history':history,'current_annotations':list(latest.values()),'adjudication_queue':disagreements,
                             'codebook_decisions':list(decisions.values()),'annotation_template':template,
                             'reference_template':reference_template,'current_references':list(references.values())}.items():
            write_jsonl(output/(name+'.jsonl'),records);write_csv(output/(name+'.csv'),records)
        # A decision ledger never silently rewrites the runtime taxonomy or gold set.
        report={'status':'complete','exit_code':0,'case_denominator':len(cases),'new_records':len(staged),
                'human_annotations':len(latest),'cases_with_annotations':len({k[0] for k in latest}),
                'human_reference_annotations':len(references),'cases_with_references':len({k[0] for k in references}),
                'category_decisions':len(decisions),'unresolved_disagreements':len(disagreements),
                'taxonomy_applied_automatically':False,'category_saturation_established':False,
                'accuracy':None,'recall':None,'run_manifest_sha256':fingerprint,
                'human_evaluation':'pending' if not latest and not references else 'partial_self_declared_human_records'}
        write_json(output/'coding_audit.json',report)
        return report
    finally:db.close()
