"""Build non-destructive, versioned motive review deliveries from saved annotations."""
from __future__ import annotations
import argparse,collections,csv,hashlib,json,re,sys,copy
from pathlib import Path
from review_agent_log_motives import ROOT,PARENT,OUT,read,write,lines,sha,now

TYPES=('prompt','commit_message','pr_description','review_comment','issue')
STATUSES=('explicit','inferred','unknown','conflicting')
LABELS={'noise_control','log_level','diagnostics','message_accuracy','performance','sensitive_information','format_consistency','requirements_change','other','unknown'}

def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()[:24]
def flat(text):return re.sub(r'\s+','',text or '').rstrip(';')
def prompt_kind(text):
    if text.startswith('Base directory for this skill:'):return 'skill_injection'
    if text.startswith('This session is being continued'):return 'session_summary'
    if text.lstrip().startswith('<task-notification>'):return 'tool_notification'
    if text.startswith('[Request interrupted'):return 'interruption'
    if len(text.strip())<15:return 'short_turn_needs_context'
    return 'conversation_turn_authorship_not_independently_verified'

def csv_table(path,rows):
    if not rows:return
    with Path(path).open('w',encoding='utf-8-sig',newline='') as f:
        fields=list(dict.fromkeys(k for r in rows for k in r));w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in rows:w.writerow({k:canonical(v) if isinstance(v,(dict,list)) else v for k,v in r.items()})

def enrich():
    target=OUT/'supplement';target.mkdir(exist_ok=False)
    receipts={r['url']:(p,r) for p in (OUT/'external_readonly').glob('*.json') for r in [json.loads(p.read_text())]}
    import agent_log_motivation_v11 as v11
    store=v11.EvidenceStore();us=read(OUT/'events.jsonl');pilot=read(OUT/'batches/001_pilot/annotations.jsonl')
    sample=next(a for a in pilot if a['pilot_number']==23);seed=next(e for e in us if e['modification_id']==sample['modification_id'])
    targets=[e for e in us if (e['repository'],e['modification_sha'])==(seed['repository'],seed['modification_sha'])]
    stem='https://api.github.com/repos/marin-community/marin/'
    objects=[]
    for suffix,kind in [('pulls/2986','pr_description'),('pulls/2984','pr_description'),('issues/2982','issue'),('issues/2982/comments?per_page=100','issue')]:
        p,r=receipts[stem+suffix];body=json.loads(r['response_text']);records=body if isinstance(body,list) else [body]
        for obj in records:
            text=((obj.get('title')+'\n\n') if obj.get('title') else '')+(obj.get('body') or '')
            subtype='issue_discussion' if isinstance(body,list) else ('referenced_prior_pr' if kind=='pr_description' else 'issue_body')
            for event in targets:
                e=dict(event,event_id=event['modification_id'])
                chain=[e['modification_id'],e['modification_sha'],'marin-community/marin#3019','prompt:25c72cb65af4d01de2bfe206']
                chain+=['marin-community/marin#'+str(obj['number'])] if 'number' in obj else ['marin-community/marin#2986','marin-community/marin#2982',str(obj['id'])]
                if suffix=='issues/2982':chain.insert(-1,'marin-community/marin#2986')
                store.add(e,kind,str(obj['id']),text,url=obj.get('html_url'),local_path=str(p),timestamp=obj.get('updated_at') or obj.get('created_at'),
                    method='explicit_reference_chain_from_modification_prompt',relation='referenced_dependency_background',
                    basis={'chain':chain,'prompt_quote':'we can use shared data again in tokenize','reference_quote':'Fixes #2982' if kind=='issue' else 'https://github.com/marin-community/marin/pull/'+str(obj['number']),
                           'not_exact_modification_pr':True},source_subtype=subtype,pr_number=obj.get('number') if kind=='pr_description' else None,
                    issue_number=2982 if kind=='issue' else None,comment_id=obj['id'] if isinstance(body,list) else None)
    lines(target/'evidence.jsonl',store.evidence.values())
    lines(target/'links.jsonl',[dict(l,modification_id=l['event_id']) for l in store.links.values()])
    outcomes=[]
    for url,(p,r) in receipts.items():
        b=json.loads(r['response_text']);state='tool_endpoint_not_supported' if r['isError'] else 'redirect_unresolved' if isinstance(b,dict) and b.get('message')=='Moved Permanently' else 'success_empty' if b==[] else 'success'
        outcomes.append({'url':url,'state':state,'receipt':str(p.relative_to(OUT)),'receipt_sha256':sha(p),'fetched_at':r['fetched_at'],
            'detail':b if state in ('tool_endpoint_not_supported','redirect_unresolved') else None})
    lines(target/'request_outcomes.jsonl',outcomes)
    print('supplement',len(store.evidence),len(store.links))

def followup():
    bd=OUT/'batches/002_followup'
    if (bd/'annotations.jsonl').exists():raise ValueError('batch_already_annotated')
    ps={p['event']['modification_id']:p for p in read(bd/'packets.jsonl')}
    seeds={a['pilot_number']:a for a in read(OUT/'batches/001_pilot/annotations.jsonl')}
    selection=json.loads((bd/'selection.json').read_text())['selection'];result=[];checks=[]
    for s in selection:
        p=ps[s['modification_id']];e=p['event'];a=copy.deepcopy(seeds[s['seed_pilot']]);n=s['seed_pilot'];b=e['observed_change'].get('before_statement') or ''
        diffs=[d for d in p['diffs'] if d.get('old_path')==e['file_path'] or d.get('new_path')==e['file_path']]
        minus='\n'.join(l[1:] for d in diffs for l in (d.get('diff') or '').splitlines() if l.startswith('-') and not l.startswith('---'))
        plus='\n'.join(l[1:] for d in diffs for l in (d.get('diff') or '').splitlines() if l.startswith('+') and not l.startswith('+++'))
        # Confirm exact changed line/statement; context+added lines allow multiline
        # statements whose only changed line is the context argument.
        new_side='\n'.join(l[1:] for d in diffs for l in (d.get('diff') or '').splitlines() if l.startswith(('+',' ')) and not l.startswith('+++'))
        first=b.splitlines()[0].strip();verified=flat(first) in flat(minus)
        obs='';status=a['status'];purpose=a['stated_purpose'] or a['contextual_inference']
        if n==1:
            verified=verified and b.startswith('console.log(');obs='diff 删除此处开发调试 console.log；提交明确说明清理 Moon aspect 调试输出。'
        elif n==7:
            verified=verified and b.startswith(('console.log(', 'console.warn('));obs='diff 移除此处 webhook 诊断输出；生产清理提交明确要求 Remove diagnostic logging。';status='explicit';purpose='清理生产 webhook 的诊断输出。'
        elif n==8:
            verified=verified and 'Invalid signature' in b and 'Signature mismatch!' in plus;obs='Invalid signature Error 改为诊断 Warn，检查变为非阻断；提交明确说明 make HMAC check non-blocking for diagnostics。'
        elif n==9:
            verified='-        asyncio.create_task(log_stats()),' in '\n'.join(d['diff'] for d in diffs) and '+    if not demo:' in '\n'.join(d['diff'] for d in diffs);obs='log_stats 从无条件任务列表移到 if not demo 分支。'
        elif n==10:
            verified=verified and '[workflow:' in plus;obs='diff 将节点名称从消息正文移至 workflow 前缀；同一提交明确说明统一节点前缀。'
        elif n==16:
            verified=verified and 'npx bmad-module-skill-forge install' in plus;obs='diff 把无效安装命令名替换为 bmad-module-skill-forge。'
        elif n==31:
            verified='-  zi [OPTIONS] [PROMPT]' in '\n'.join(d['diff'] for d in diffs) and '+  xi [OPTIONS] [PROMPT]' in '\n'.join(d['diff'] for d in diffs);obs='CLI 帮助文本中 zi 命令及配置路径改为 xi。'
        elif n==33:
            verified=verified and ('print(' in plus);obs='diff 保留输出文本，折行或删除无插值 f 前缀；提交明确说明修复 Ruff lint。'
        elif n==36:
            replacement=b.replace('(ctx,','(logCtx,',1)
            verified=verified and flat(replacement) in flat(new_side);obs='同一 diff 将此日志的 ctx 参数改为从调用方 ctx 派生的 logCtx，其他日志内容保持。'
        linked={v['evidence_id']:v for v in p['sources']}
        valid_citations=[]
        for c in a['citations']:
            if c['evidence_id'] in linked and c['quote'] in linked[c['evidence_id']]['text']:valid_citations.append(c)
        verified=bool(verified and valid_citations)
        a.update(modification_id=e['modification_id'],pilot_number=None,seed_pilot=n,reviewed_at=now(),
            observed_change_review=obs or '本批规则无法验证目标变化。',citations=valid_citations,
            target_anchor={'repository':e['repository'],'modification_sha':e['modification_sha'],'file_path':e['file_path'],'before_lines':e['observed_change']['before_lines'],'after_lines':e['observed_change']['after_lines']},
            review_scope='assistant reviewed event roster and shared source purpose; exact per-event diff predicates verified by code',
            status=status if verified else 'unknown',labels=a['labels'] if verified else ['unknown'],
            stated_purpose=purpose if verified and status=='explicit' else None,contextual_inference=purpose if verified and status=='inferred' else None,
            direct_correspondence=obs if verified and status=='explicit' else None,
            unknown_reason=None if verified else 'scoped_diff_predicate_did_not_establish_correspondence')
        if not verified:
            for c in a['citations']:c['role']='context'
        checks.append({'modification_id':e['modification_id'],'seed_pilot':n,'target_predicate_pass':verified})
        result.append(a)
    lines(bd/'annotations.jsonl',result);lines(bd/'target_checks.jsonl',checks)
    write(bd/'review_receipt.json',{'at':now(),'count':len(result),'distribution':dict(collections.Counter(a['status'] for a in result)),
        'target_predicate_pass':sum(x['target_predicate_pass'] for x in checks),'reviewer':'same_assistant_plus_exact_diff_checks','independent_evaluation':False})
    print('followup',collections.Counter(a['status'] for a in result), 'failed',[x for x in checks if not x['target_predicate_pass']])

def validate_annotation(a,event,evidence,links):
    if a['status'] not in STATUSES:raise ValueError('invalid_status')
    if not a['labels'] or set(a['labels'])-LABELS:raise ValueError('invalid_labels')
    t=a['target_anchor']
    for k in ('repository','modification_sha','file_path'):
        if t.get(k)!=event[k]:raise ValueError('wrong_target_'+k)
    for side in ('before','after'):
        if t.get(side+'_lines')!=event['observed_change'].get(side+'_lines'):raise ValueError('wrong_target_lines')
    support=[];positions=collections.defaultdict(lambda:collections.defaultdict(set))
    for c in a.get('citations',[]):
        ev=evidence.get(c['evidence_id'])
        if ev is None or not c.get('quote') or c['quote'] not in ev['text']:raise ValueError('invalid_quote')
        if c.get('quote_start') is not None and ev['text'][c['quote_start']:c['quote_start']+len(c['quote'])] != c['quote']:
            raise ValueError('quote_offset_mismatch')
        edges=links.get((event['modification_id'],c['evidence_id']),[])
        if not edges:raise ValueError('unassociated_evidence')
        if c.get('role')=='purpose_support':
            if all(x['relation'] in ('introduction_background','referenced_dependency_background') for x in edges):raise ValueError('background_only_purpose')
            support.append(c)
            positions[c.get('claim_key','event_purpose')][c.get('position','supports')].add(ev.get('equivalence_group',c['evidence_id']))
    conflict=any(v.get('supports') and v.get('opposes') and v['supports']!=v['opposes'] for v in positions.values())
    if conflict and a['status']!='conflicting':raise ValueError('unresolved_conflict')
    if a['status']=='conflicting' and not conflict:raise ValueError('conflict_without_distinct_opposing_sources')
    if a['status'] in ('explicit','inferred','conflicting') and not support:raise ValueError('missing_support')
    if a['status']=='explicit' and (not a.get('stated_purpose') or not a.get('direct_correspondence')):raise ValueError('explicit_missing_correspondence')
    if a['status']=='inferred' and not a.get('contextual_inference'):raise ValueError('inferred_missing_inference')
    if a['status']=='unknown' and not a.get('unknown_reason'):raise ValueError('unknown_missing_reason')
    return True


def build(delivery_name='delivery_v1'):
    if not re.fullmatch(r'delivery_v[0-9]+',delivery_name): raise ValueError('invalid_delivery_name')
    target=OUT/delivery_name;target.mkdir(exist_ok=False)
    events=read(OUT/'events.jsonl');evs=read(OUT/'evidence.jsonl')
    supplemental=read(OUT/'supplement/evidence.jsonl');aliases=[];alias_ids={}
    for incoming in supplemental:
        matches=[e for e in evs if e['source_type']==incoming['source_type'] and e.get('source_url') and e.get('source_url')==incoming.get('source_url') and e['text'].replace('\r\n','\n').strip()==incoming['text'].replace('\r\n','\n').strip()]
        if matches:
            canonical_source=matches[0];alias_ids[incoming['evidence_id']]=canonical_source['evidence_id']
            aliases.append({'fetched_evidence_id':incoming['evidence_id'],'retained_evidence_id':canonical_source['evidence_id'],'basis':'same source_type, exact source URL, CRLF-normalized trimmed text','new_receipt':incoming['source_local_path']})
            canonical_source.setdefault('supplemental_source_locators',[]).append({'local_path':incoming['source_local_path'],'source_time':incoming['source_time']})
        else:evs.append(incoming)
    added_links=read(OUT/'supplement/links.jsonl')
    for l in added_links:l['evidence_id']=alias_ids.get(l['evidence_id'],l['evidence_id'])
    links=read(OUT/'evidence_links.jsonl')+added_links
    lines(target/'supplemental_evidence_aliases.jsonl',aliases)
    # Parent rows are preserved verbatim in evidence.jsonl. The delivery adds
    # conservative equivalence groups for CRLF/trailing whitespace only.
    for ev in evs:
        ev['equivalence_group']=digest([ev['source_type'],ev['repository'].lower(),ev.get('source_subtype'),ev['source_id'],ev['text'].replace('\r\n','\n').strip()])
        ev['prompt_content_kind']=prompt_kind(ev['text']) if ev['source_type']=='prompt' else None
    evidence={e['evidence_id']:e for e in evs};assert len(evidence)==len(evs)
    indexed=collections.defaultdict(list)
    for l in links:indexed[l['modification_id'],l['evidence_id']].append(l)
    annotations=[]
    for bd in sorted((OUT/'batches').iterdir()):
        if (bd/'annotations.jsonl').exists():
            for a in read(bd/'annotations.jsonl'):a['batch_id']=bd.name;annotations.append(a)
    anns={a['modification_id']:a for a in annotations};assert len(anns)==len(annotations)
    for e in events:
        if e['modification_id'] in anns:validate_annotation(anns[e['modification_id']],e,evidence,indexed)
    oldmap={r['event_id']:r['modification_id'] for r in read(PARENT/'delivery/association_to_modification.jsonl')}
    inherited=collections.defaultdict(list)
    for a in read(PARENT/'reviewed_motive_annotations.jsonl'):inherited[oldmap[a['event_id']]].append(a)
    lines(target/'inherited_annotations.jsonl',[dict(a,modification_id=mid) for mid,aa in inherited.items() for a in aa])
    gaps=collections.defaultdict(lambda:collections.defaultdict(set))
    with (PARENT/'stage3_final/unresolved_records.jsonl').open(encoding='utf-8-sig') as f:
        for s in f:
            r=json.loads(s);mid=oldmap.get(r.get('event_id'))
            if mid:gaps[mid][(r.get('source_type'),r.get('reason'))].add(r.get('endpoint') or r.get('source_id') or '')
    summary=[];unresolved=[];event_sources=collections.defaultdict(set)
    for l in links:event_sources[l['modification_id']].add(l['source_type'])
    for e in events:
        mid=e['modification_id'];a=anns.get(mid)
        if not a and inherited.get(mid):
            # Do not discard prior conclusions; keep their narrower association scope.
            prior=inherited[mid][0]
            a={'status':prior['status'],'labels':prior['labels'],'review_state':'inherited_association_review',
               'observed_change_review':'继承此前关联层样例；本轮未重新判读。','stated_purpose':prior.get('stated_purpose'),
               'contextual_inference':prior.get('inference'),'unknown_reason':None,'citations':prior.get('citations',[]),
               'conclusion_scope':'prior_association_only; no automatic upgrade of every candidate linkage'}
        if not a:
            a={'status':'unknown','labels':['unknown'],'review_state':'pending_semantic_review','stated_purpose':None,'contextual_inference':None,
               'observed_change_review':'上游记录已保留；尚未逐事件解释材料。','unknown_reason':'not_yet_semantically_reviewed',
               'citations':[],'conclusion_scope':'no_motive_claim'}
        summary.append(dict(e,motive_status=a['status'],motive_labels=a['labels'],review_state=a['review_state'],
           observed_change_review=a.get('observed_change_review'),stated_purpose=a.get('stated_purpose'),contextual_inference=a.get('contextual_inference'),
           unknown_reason=a.get('unknown_reason'),citations=a.get('citations'),conclusion_scope=a.get('conclusion_scope'),
           source_types=sorted(event_sources[mid]),current_batch=anns.get(mid,{}).get('batch_id')))
        for (typ,reason),locs in gaps[mid].items():
            unresolved.append({'modification_id':mid,'source_type':typ,'reason':reason,'locators':sorted(locs),
                'scope':'inherited_request_gap_not_proof_source_type_is_absent','source_type_has_other_available_evidence':typ in event_sources[mid]})
        if a['status']=='unknown':unresolved.append({'modification_id':mid,'source_type':'motive','reason':a.get('unknown_reason'),'scope':'motive_review'})
    lines(target/'log_modification_reviews.jsonl',summary);csv_table(target/'log_modification_reviews.csv',summary)
    lines(target/'motive_evidence.jsonl',evs);lines(target/'evidence_links.jsonl',links);lines(target/'annotations.jsonl',annotations)
    lines(target/'unresolved_records.jsonl',unresolved)
    pending=[e for e in summary if e['review_state']=='pending_semantic_review']
    csv_table(target/'pending_events.csv',pending);lines(target/'pending_events.jsonl',pending)
    # Persist mechanical triage in chunks; never call these semantic reviews.
    for i in range(0,len(pending),100):
        chunk=pending[i:i+100]
        write(OUT/f'batches/triage_{i//100+1:03d}/progress.json',{'at':now(),'phase':'source_inventory_complete_semantic_review_pending',
            'modification_ids':[e['modification_id'] for e in chunk],'count':len(chunk),'reviewed':0})
    eq=collections.defaultdict(list)
    for ev in evs:eq[ev['equivalence_group']].append(ev['evidence_id'])
    lines(target/'evidence_equivalence_groups.jsonl',[{'equivalence_group':k,'evidence_ids':v,'policy':'same source identity plus CRLF normalization and outer whitespace trim; originals retained'} for k,v in eq.items() if len(v)>1])
    metrics={'at':now(),'unique_events':len(summary),'association_rows':sum(e['association_count'] for e in summary),
       'current_assistant_reviewed':len(annotations),'pilot_reviewed':40,'followup_reviewed':len(annotations)-40,
       'inherited_only':sum(e['review_state']=='inherited_association_review' for e in summary),'pending_semantic_review':len(pending),
       'motive_distribution':{s:sum(e['motive_status']==s for e in summary) for s in STATUSES},
       'current_review_distribution':dict(collections.Counter(a['status'] for a in annotations)),
       'unknown_reasons':dict(collections.Counter(e['unknown_reason'] for e in summary if e['motive_status']=='unknown')),
       'evidence_rows':len(evs),'new_evidence_rows':len(supplemental)-len(aliases),'supplemental_source_rows_readback':len(supplemental),'reused_parent_sources':len(aliases),'relation_edges':len(links),
       'normalized_equivalence_groups_with_duplicates':sum(len(v)>1 for v in eq.values()),'normalized_duplicate_excess':sum(len(v)-1 for v in eq.values()),
       'prompt_content_kinds':dict(collections.Counter(e['prompt_content_kind'] for e in evs if e['source_type']=='prompt')),
       'source_coverage':{t:{'events':sum(t in event_sources[e['modification_id']] for e in summary),'denominator':len(summary),
             'fraction':sum(t in event_sources[e['modification_id']] for e in summary)/len(summary)} for t in TYPES},
       'classification_not_independent_evaluation':True,'complete_semantic_review':not pending,
       'conflict_distribution_interpretation':'No established opposing purpose claims in reviewed subset; unreviewed sources not cleared of conflicts.'}
    write(target/'statistics.json',metrics)
    write(OUT/'progress.json',{'phase':'incremental_review_delivered_remaining_semantic_review_pending','at':now(),**{k:metrics[k] for k in ('unique_events','current_assistant_reviewed','pending_semantic_review','inherited_only')},'resume_from':delivery_name+'/pending_events.jsonl'})
    print(json.dumps(metrics,ensure_ascii=False,indent=2))

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('command',choices=['enrich','followup','build']);ap.add_argument('--delivery-name',default='delivery_v1');args=ap.parse_args()
    if args.command=='build':build(args.delivery_name)
    else:globals()[args.command]()
