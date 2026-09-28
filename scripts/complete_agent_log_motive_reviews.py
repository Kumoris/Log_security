"""Resumable unique-event review with explicit human/assistant vs mechanical scopes."""
from __future__ import annotations
import json,re,sys,collections,hashlib,csv,copy,argparse
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
OLD=ROOT/'outputs/agent_log_motive_review_20260924'
PARENT=ROOT/'outputs/agent_log_three_stage_complete_20260923'
OUT=ROOT/'outputs/agent_log_motive_completion_20260924'
sys.path.insert(0,str(ROOT/'scripts'))
from review_agent_log_motives import read,write,lines,sha,now
from agent_log_review_delivery import csv_table,validate_annotation

def norm(t):return re.sub(r'\s+',' ',t or '').strip()

def diff_rows(diff):
    old=new=None
    for raw in (diff or '').splitlines():
        m=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@',raw)
        if m:old,new=int(m[1]),int(m[2]);continue
        if old is None or not raw or raw.startswith(('+++','---','\\')):continue
        tag=raw[0]
        if tag not in ' +-':continue
        yield {'tag':tag,'old_line':old if tag!='+' else None,'new_line':new if tag!='-' else None,'text':raw[1:]}
        old+=tag!='+';new+=tag!='-'

def inspect_change(e,c):
    obs=e['observed_change'];bs=obs.get('before_lines') or [None,None];a=obs.get('after_lines') or [None,None]
    excerpts=[];removed=[];added=[];matched=[]
    for d in c['diffs']:
        if e['file_path'] not in (d.get('old_path'),d.get('new_path')):continue
        rows=list(diff_rows(d['diff']));near=[]
        for j,r in enumerate(rows):
            hit=any(isinstance(start,int) and isinstance(r[k],int) and start<=r[k]<=end for k,(start,end) in [('old_line',bs),('new_line',a)])
            if hit:
                matched.append(r)
                if r['tag']=='-':removed.append(r)
                if r['tag']=='+':added.append(r)
                near.extend(rows[max(0,j-4):j+5])
        seen=set();near=[x for x in near if not ((key:=(x['tag'],x['old_line'],x['new_line'],x['text'])) in seen or seen.add(key))]
        if near:excerpts.append({'file_change_id':d['file_change_id'],'diff_basis_sha':d['diff_basis_sha'],'diff_target_sha':d['diff_target_sha'],'path':e['file_path'],'rows':near})
    before=obs.get('before_statement');after=obs.get('after_statement')
    if removed or added:kind='target_lines_changed'
    elif before==after and before:kind='statement_unchanged_in_dependency_or_context_change'
    elif obs['kind']=='deleted' and any(x['tag']==' ' for x in matched):kind='upstream_deleted_but_target_retained_as_diff_context'
    elif not excerpts:kind='no_target_span_in_attached_diff'
    else:kind='context_only'
    return {'classification':kind,'before_statement':before,'after_statement':after,'target_diff_excerpts':excerpts,
      'removed_target_lines':removed,'added_target_lines':added,'note':'原始上游变化类型保留；此处独立核验实际目标行，不由 deleted 推断输出消失。'}

def sources():
    ev={e['evidence_id']:e for e in read(OLD/'delivery_v2/motive_evidence.jsonl')};links=collections.defaultdict(list)
    for l in read(OLD/'delivery_v2/evidence_links.jsonl'):links[l['modification_id']].append(l)
    return ev,links

def initialize():
    assert json.loads((OUT/'guard_receipt.json').read_text())['parent_code_matched']
    if (OUT/'inventory.jsonl').exists():raise ValueError('already_initialized')
    events=read(OLD/'delivery_v2/log_modification_reviews.jsonl');contexts={c['modification_id']:c for c in read(OUT/'contexts.jsonl')};ev,links=sources()
    inventory=[]
    for e in events:
        inspected=inspect_change(e,contexts[e['modification_id']]);state='prior_review_pending_audit' if e['review_state']=='assistant_reviewed' else 'pending'
        inventory.append(dict(e,review_state=state,motive_status=None,motive_labels=[],prior_motive_status=e['motive_status'],
             current_observation=inspected,evidence_ids=sorted({l['evidence_id'] for l in links[e['modification_id']]})))
    lines(OUT/'inventory.jsonl',inventory)
    # Grouping shares a commit context without conflating individual log events.
    groups=collections.defaultdict(list)
    for e in inventory:groups[e['repository'],e['modification_sha']].append(e)
    gs=[]
    for i,((repo,commit),es) in enumerate(sorted(groups.items()),1):
        source_ids=sorted({x for e in es for x in e['evidence_ids']});texts=[ev[x] for x in source_ids]
        commit_sources=[v for v in texts if v['source_type']=='commit_message']
        commit_text=min(commit_sources,key=lambda v:len(v['text']))
        # Text matching selects passages ONLY after exact upstream association;
        # it neither creates links nor determines motive status.
        focus=[]
        for v in texts:
            if v['source_type'] in ('commit_message','pr_description'):
                segments=[(0,min(len(v['text']),1800))]
            elif v['source_type']=='prompt' and v.get('prompt_content_kind') in ('skill_injection','session_summary','tool_notification','interruption','short_turn_needs_context'):
                segments=[]
            else:
                needles=set()
                for e in es:
                    b=e['observed_change'].get('before_statement') or ''
                    needles.update(re.findall(r'"([^"\n]{15,100})"|\'([^\'\n]{15,100})\'',b))
                literals=[x for pair in needles for x in pair if x]
                hits=[v['text'].find(x) for x in literals if x in v['text']]
                hits += [m.start() for m in re.finditer(r'(?i)\blogging\b|\blog messages?\b|\bdebug logs?\b|\bconsole\.(log|warn|error)|\bdiagnostic|日志|ログ',v['text'])]
                segments=[(max(0,h-120),min(len(v['text']),h+700)) for h in hits[:3]]
            for start,end in segments:
                quote=v['text'][start:end]
                if quote:focus.append({'evidence_id':v['evidence_id'],'source_type':v['source_type'],'quote_start':start,'quote':quote,'source_chars':len(v['text'])})
        gs.append({'group_number':i,'repository':repo,'modification_sha':commit,'event_ids':[e['modification_id'] for e in es],
            'title':commit_text['text'].splitlines()[0],'commit_source':commit_text['evidence_id'],
            'source_ids':source_ids,'focus':focus})
    lines(OUT/'commit_groups.jsonl',gs)
    write(OUT/'initial_counts.json',{'at':now(),'total':1757,'prior_reviewed':110,'inherited_only_to_review':1,'pending_prior':1646,'remaining_new_reviews':1647,
      'no_any_source':sum(not e['evidence_ids'] for e in inventory),
      'missing_sources':{t:sum(not any(ev[x]['source_type']==t for x in e['evidence_ids']) for e in inventory) for t in ('prompt','commit_message','pr_description','review_comment','issue')},
      'observed_diff_kinds':dict(collections.Counter(e['current_observation']['classification'] for e in inventory))})
    print(json.dumps(json.loads((OUT/'initial_counts.json').read_text()),ensure_ascii=False,indent=2))

def show_groups(start,end):
    ev,links=sources();es={e['modification_id']:e for e in read(OUT/'inventory.jsonl')}
    for g in read(OUT/'commit_groups.jsonl'):
        if not start<=g['group_number']<=end:continue
        targets=[es[mid] for mid in g['event_ids'] if es[mid]['review_state']=='pending']
        if not targets:continue
        kinds=collections.Counter(e['current_observation']['classification'] for e in targets)
        print('\nG',g['group_number'],g['repository'],len(targets),dict(kinds),g['title'])
        seen=set();remaining=2400
        for f in g['focus']:
            if f['source_type'] not in ('commit_message','pr_description'):continue
            text=norm(f['quote'])
            if text in seen:continue
            seen.add(text)
            if remaining<=0:break
            clip=text[:min(remaining,1400)];remaining-=len(clip)
            print('SOURCE',f['evidence_id'],f['source_type'],clip)
        for e in targets:
            o=e['current_observation'];b=norm(o['before_statement']);a=norm(o['after_statement'])
            print(' E',e['modification_id'],e['file_path'],o['classification'],b[:150],'=>',a[:100])


from agent_log_review_delivery import digest,canonical,TYPES
from motive_completion_decisions import RULES,GROUP_NOTES
import shutil

def exclusive_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f:json.dump(obj,f,ensure_ascii=False,indent=2)

def verified_events():
    events=read(OUT/'inventory.jsonl');contexts={c['modification_id']:c for c in read(OUT/'contexts.jsonl')};repairs=[]
    for e in events:
        o=e['current_observation'];changed=False;adjusted=copy.deepcopy(e);checks=[]
        for side,key in [('before','old'),('after','new')]:
            ss=(o[side+'_statement'] or '').splitlines();span=e['observed_change'].get(side+'_lines') or [None,None]
            rows=o['removed_target_lines' if side=='before' else 'added_target_lines'];bad=False
            for r in rows:
                off=r[key+'_line']-span[0]
                if 0<=off<len(ss) and norm(ss[off]).rstrip(';') not in norm(r['text']).rstrip(';'):bad=True
            if not bad:continue
            matches=[]
            for d in contexts[e['modification_id']]['diffs']:
                if d.get(key+'_path')!=e['file_path']:continue
                rs=[r for r in diff_rows(d['diff']) if r['tag'] in (('-',' ') if side=='before' else ('+',' '))];n=len(ss)
                for j in range(len(rs)-n+1):
                    rr=rs[j:j+n]
                    if n and all(rr[z][key+'_line']==rr[0][key+'_line']+z for z in range(n)) and norm(o[side+'_statement']) in norm('\n'.join(r['text'] for r in rr)):
                        matches.append([rr[0][key+'_line'],rr[-1][key+'_line']])
            matches=list({tuple(x) for x in matches})
            if len(matches)!=1:raise ValueError('ambiguous_actual_target_span:'+e['modification_id'])
            fixed=list(matches[0]);adjusted['observed_change'][side+'_lines']=fixed;changed=True
            checks.append({'side':side,'original_span':span,'verified_span':fixed,'method':'unique full statement match within same path and parent/target SHA unified diff; never nearest time/keyword'})
        if changed:
            e['current_observation']=inspect_change(adjusted,contexts[e['modification_id']]);e['span_corrections']=checks
            repairs.append({'modification_id':e['modification_id'],'repository':e['repository'],'modification_sha':e['modification_sha'],'file_path':e['file_path'],'corrections':checks,
               'upstream_fields_unchanged':True,'motive_conclusion_changed':False,'affected_batch':'001_review'})
        else:e['span_corrections']=[]
    return events,contexts,repairs

def exact_citation(eid,quote,ev,role='context',claim='event_purpose'):
    if quote not in ev[eid]['text']:raise ValueError('approved_quote_not_in_source:'+eid+':'+quote)
    return {'evidence_id':eid,'quote':quote,'quote_start':ev[eid]['text'].index(quote),'role':role,'claim_key':claim,'position':'supports'}

def supplemental(ev,links,events):
    p=OUT/'external_readonly/issue3_1.json';r=json.loads(p.read_text());obj=json.loads(r['response_text'])
    txt=obj['title']+'\n\n'+obj['body'];eid=digest(['issue',obj['html_url'],txt]);ev=copy.deepcopy(ev)
    ev[eid]={'evidence_id':eid,'source_type':'issue','source_subtype':'issue_body','source_id':str(obj['id']),'issue_number':3,
      'repository':'dipasqualew/vibereq','source_url':obj['html_url'],'source_local_path':str(p),'source_time':obj['updated_at'],
      'source_time_status':'available','created_at':obj['created_at'],'retrieved_at':r['fetched_at'],'text':txt,'excerpt':txt,
      'excerpt_truncated':False,'content_sha256':hashlib.sha256(txt.encode()).hexdigest(),'equivalence_group':digest(['issue',str(obj['id']),txt]),
      'source_locators':[{'url':obj['html_url'],'local_path':str(p),'time':obj['updated_at']}],'prompt_content_kind':None}
    all_links=copy.deepcopy(links);pe=ev['0dd6c6febbccffa7a9c107b2']
    for e in events:
        mid=e['modification_id']
        if not any(l['evidence_id']==pe['evidence_id'] and l['relation']=='modification_session_context' for l in links[mid]):continue
        basis={'chain':[mid,e['modification_sha'],pe['checkpoint_pk'],pe['session_id'],pe['turn_id'],obj['html_url']],
            'reference_quote':'Plan: Logging and OpenTelemetry Setup (Issue #3)','reference_source':pe['evidence_id'],
            'repository_resolution':'same repository as exact modification checkpoint/session; not a time or keyword join'}
        all_links[mid].append({'modification_id':mid,'evidence_id':eid,'relation':'modification_prompt_referenced_issue',
           'source_type':'issue','repository':e['repository'],'modification_sha':e['modification_sha'],'file_path':e['file_path'],
           'association_methods':['explicit_issue_reference_in_modification_prompt'],'association_basis':basis,
           'session_id':pe['session_id'],'checkpoint_pk':pe['checkpoint_pk'],'issue_number':3,'original_event_ids':e.get('association_event_ids',[]),
           'original_link_ids':[],'representative_chains':[]})
    return ev,all_links

def scope_check(rule,e,c):
    kind=rule[6];o=e['current_observation'];b=o['before_statement'] or '';a=o['after_statement'] or '';path=e['file_path']
    near=[r for d in o['target_diff_excerpts'] for r in d['rows']]
    plus='\n'.join(r['text'] for r in near if r['tag']=='+');minus='\n'.join(r['text'] for r in o['removed_target_lines'])
    ds=[d for d in c['diffs'] if path in (d.get('old_path'),d.get('new_path'))]
    allplus='\n'.join(r['text'] for d in ds for r in diff_rows(d['diff']) if r['tag']=='+')
    changed=o['classification']=='target_lines_changed'
    if kind=='banner':return changed and path.endswith('/ui.js') and 'console.log' in b
    if kind=='deleted_file':return changed and any(d['old_path']==path and d['new_path'] is None for d in ds)
    if kind=='deleted_auto_commit':return changed and path.endswith('/auto_commit.go') and any(d['new_path'] is None for d in ds)
    if kind=='vibereq_logger':
        pairs={'c7ed8ece00e2c08011de0373':'ctx.logger.debug("Finding not in diff",',
               '4f490ef9b91efe76a2ecd0e0':'logger?.error("Failed to get PR head commit",',
               'c9c6e3480acb0d754133f194':'logger?.error("Failed to create review",'}
        return changed and e['modification_id'] in pairs and pairs[e['modification_id']] in allplus
    if kind=='v2_guard':return changed and 'compact transcript redaction failed' in b and 'if settings.IsCheckpointsV2Enabled(ctx)' in plus
    if kind=='context_arg':
        if not changed:return False
        first=b.splitlines()[0].strip()
        if not any(first.rstrip(';') in r['text'].strip().rstrip(';') for r in o['removed_target_lines']):return False
        if 'context.Background()' in first:return first.replace('context.Background()','ctx') in plus
        if '(h.logCtx,' in first:return first.replace('(h.logCtx,','(logCtx,') in plus or first.replace('(h.logCtx,','(logging.WithComponent(h.ctx, "checkpoint"),') in plus
        return False
    if kind=='review_reword':return changed and 'resolveLatestCheckpoint failed' in minus and '"no checkpoint metadata resolved"' in plus
    if kind=='notifier_context':return changed and 'WarnContext(context.Background()' in minus and 'WarnContext(cmdCtx' in plus and 'context.WithoutCancel(ctx)' in plus
    if kind=='screen_cancel':return b.startswith('logger.error') and any(r['tag']==' ' and b.splitlines()[0].strip()==r['text'].strip() for r in near) and 'if screen_gone(self, e):' in plus and 'return' in plus
    if kind=='als_prefix':
        if not changed:return False
        mm=re.search(r'"(\[[^]]+\]) ([^"\n]+)"',b)
        return bool(mm and ('"'+mm[2]+'"') in plus)
    if kind=='als_field':return changed and 'clerkOrgId,' in minus and 'Failed to insert activity batch' in b and 'clerkOrgId' not in a and bool(a)
    if kind=='als_complete':return changed and 'Knock notification triggered' in minus
    if kind=='rebrand':return changed and any(old in minus and new in plus for old,new in [('~/.brain/','~/.osabio/'),('BRAIN_WORKSPACE_ID','OSABIO_WORKSPACE_ID'),('Brain web UI','Osabio web UI')])
    if kind=='map_help':return changed and 'brain map <dir>' in minus and 'brain unmap <dir>' in minus
    if kind=='tokenize_removed':return changed and path.endswith('/tokenize.py') and b.startswith('logger.info') and bool(minus)
    if kind=='default_logger':return changed and b.startswith('log.') and a==b.replace('log.','slog.Default().',1)
    if kind=='slog_package':return changed and b.startswith('slog.Default().') and a==b.replace('slog.Default().','slog.',1)
    if kind=='ratchet_path':return changed and 'extension/COVERAGE_RATCHET.md' in minus and 'docs/development/ratchets.md' in plus
    if kind=='write_step':return changed and b.startswith('_write_step(') and a==b[1:]
    if kind=='trade_skip':return changed and 'self._logger.warning' in minus and 'self._logger.info' in plus and "OPERATION_EMOJIS['skip']" in plus
    if kind=='stream_errors':return changed and 'Empty response from model' in b and 'streamErrors,' in plus
    if kind=='warning_debug':return changed and path=='watch/client.py' and 'logger.warning' in minus and 'logger.debug' in plus and 'watch.client disabled' in b
    if kind=='loop_move':return changed and path=='reck/loop.py' and b==a and bool(b) and any(d.get('old_path') is None for d in ds)
    if kind=='debug_warning':return changed and path=='watch/client.py' and 'logger.debug' in minus and 'logger.warning' in plus and 'error_code' in plus
    raise ValueError('unrecognized_scope:'+kind)

def observation_text(e):
    o=e['current_observation'];k=o['classification'];bl=e['observed_change'].get('before_lines');al=e['observed_change'].get('after_lines')
    head=f"{e['file_path']}；目标行 {bl} → {al}。"
    if k=='target_lines_changed':
        if o['before_statement']==o['after_statement']:return head+'目标在 diff 中发生搬移/重排，记录内语句文本前后相同；不能直接称删除输出。'
        if o['after_statement'] is None:return head+'目标旧行在 diff 中有变更；上游 after 为空，附近存在替换的可能，不能仅凭 deleted 确认停止输出。'
        return head+'目标行有实际修改；before/after 原文及带坐标 diff 保存在 current_observation。'
    if k=='statement_unchanged_in_dependency_or_context_change':return head+'记录内日志/调用文本相同；当前事件反映依赖、外围逻辑或位置变化。'
    if k=='upstream_deleted_but_target_retained_as_diff_context':return head+'上游标 deleted，但目标在附带 diff 中仍是保留上下文；不据此推断删日志。'
    return head+'附带 diff 未建立目标语句的实际增删对应；保留原事件并标记关联证据局限。'

def annotate(e,g,c,ev,links):
    mid=e['modification_id'];available={l['evidence_id'] for l in links[mid]};checks=[];accepted=[]
    for r in RULES:
        if r[0]!=g['group_number']:continue
        eligible=r[1] in available and any(l['evidence_id']==r[1] and l['relation'] not in ('introduction_background','referenced_dependency_background') for l in links[mid])
        ok=bool(eligible and scope_check(r,e,c));checks.append({'scope':r[6],'source':r[1],'pass':ok})
        if ok:accepted.append(r)
    a={'modification_id':mid,'review_state':'assistant_reviewed','reviewed_at':now(),'reviewer':'Codex; assistant development review; not independent human evaluation',
       'review_method':'assistant_read_commit_context_and_targeted_source_passages_plus_exact_per_event_diff_checks',
       'review_scope':'提交/PR上下文及关联 prompt、评论、issue 的目标片段；保留全文但不声称逐字人工通读全部材料。',
       'target_anchor':{k:e[k] for k in ('repository','modification_sha','file_path')},'observed_change_review':observation_text(e),
       'group_number':g['group_number'],'group_context_note':GROUP_NOTES.get(g['group_number'],'已审读该修改提交的上下文；没有经目标变化核准的目的不作确定性归因。'),
       'status':'unknown','labels':['unknown'],'stated_purpose':None,'contextual_inference':None,'direct_correspondence':None,
       'unknown_reason':None,'citations':[],'scope_checks':checks,'conclusion_scope':'physical event only; candidate Agent lineage and stage1/2 admission unchanged',
       'conflict_review':{'state':'no_supported_opposing_purpose_identified_in_reviewed_passages','scope':'targeted review; not proof no conflict exists anywhere'}}
    for s in ('before','after'):a['target_anchor'][s+'_lines']=e['observed_change'].get(s+'_lines')
    if accepted:
        statuses={r[3] for r in accepted};assert len(statuses)==1
        a['status']=accepted[0][3];a['labels']=sorted({t for r in accepted for t in r[4]});purpose='；'.join(r[5] for r in accepted)
        a['stated_purpose']=purpose if a['status']=='explicit' else None;a['contextual_inference']=purpose if a['status']=='inferred' else None
        a['direct_correspondence']='; '.join(r[6] for r in accepted)+'：精确目标 diff 条件已通过，详见 scope_checks/current_observation。'
        a['citations']=[exact_citation(r[1],r[2],ev,'purpose_support',r[6]) for r in accepted]
        if g['group_number']==82:
            pe=ev['0dd6c6febbccffa7a9c107b2'];a['citations'].append(exact_citation(pe['evidence_id'],'use logger only for operational logging',ev,'purpose_support','operational_structured_logging'))
        if g['group_number']==165:
            a['direct_correspondence']='同一 PR 的旧版评审 hunk 在 resumeFromCurrentBranch 中引用完整旧消息和 !found 条件；最终同文件目标行 289 改为 no checkpoint metadata resolved 并移除 err 字段。不是按时间/关键词关联，不宣称评审 SHA 等于最终 SHA。'
    else:
        k=e['current_observation']['classification']
        reason={'statement_unchanged_in_dependency_or_context_change':'unchanged_statement_no_supported_dependency_motive',
          'upstream_deleted_but_target_retained_as_diff_context':'upstream_deleted_context_retained_no_corresponding_purpose',
          'no_target_span_in_attached_diff':'target_diff_correspondence_unavailable','context_only':'only_context_change_no_supported_purpose'}.get(k,
          'linked_context_does_not_establish_event_specific_purpose')
        if k=='target_lines_changed' and e['current_observation']['before_statement']==e['current_observation']['after_statement']:reason='relocated_or_reformatted_statement_no_supported_purpose'
        a['unknown_reason']=reason
    # Every reviewed event has a real, exact source excerpt; context is never
    # silently promoted to purpose. Long texts remain in the evidence table.
    candidates=[g['commit_source']]+[x for x in g['source_ids'] if ev[x]['source_type']=='pr_description'][:1]
    for eid in candidates:
        if eid not in available or any(x['evidence_id']==eid for x in a['citations']):continue
        q=ev[eid]['text'][:700];a['citations'].append(exact_citation(eid,q,ev))
    a['available_source_types']=sorted({ev[x]['source_type'] for x in available});a['missing_source_types']=[t for t in TYPES if t not in a['available_source_types']]
    a['inspected_event_fingerprint']=digest([e['observed_change'],e['current_observation'],g['commit_source'],a['scope_checks']])
    return a

def indexed_links(links):return {(mid,eid):[l for l in ll if l['evidence_id']==eid] for mid,ll in links.items() for eid in {x['evidence_id'] for x in ll}}

def batch_validate(annotations,events,ev,links):
    indexed=indexed_links(links);ids=[a['modification_id'] for a in annotations];assert len(ids)==len(set(ids))
    for a in annotations:
        assert a['review_state']=='assistant_reviewed';validate_annotation(a,events[a['modification_id']],ev,indexed)
        if a['status']=='unknown':assert a['unknown_reason'] and not a['stated_purpose'] and not a['contextual_inference']
        if a['status']=='explicit':assert any(x['role']=='purpose_support' for x in a['citations'])
    return {'status':'PASS','events':len(ids),'checks':{'unique_event_ids':True,'exact_quote_offsets':True,'source_edges_exist':True,'target_identity_and_spans':True,
       'motive_status_invariants':True,'background_not_purpose':True,'opposed_claim_conflict_handling':True},'at':now()}

def load_batches():
    aa=[]
    for p in sorted((OUT/'batches').glob('*/annotations.jsonl')):
        if not (p.parent/'validation.json').exists():raise ValueError('unvalidated_batch:'+str(p.parent))
        assert json.loads((p.parent/'validation.json').read_text())['status']=='PASS';aa+=read(p)
    assert len({a['modification_id'] for a in aa})==len(aa)
    return aa

def save_progress(aa,total=1757):
    write(OUT/'progress.json',{'at':now(),'phase':'reviews_complete_pending_delivery_validation' if len(aa)==total else 'reviewing',
      'total':total,'reviewed':len(aa),'pending':total-len(aa),'motive_distribution_reviewed_only':dict(collections.Counter(a['status'] for a in aa)),
      'unreviewed_motive_status':None,'completed_batches':len(list((OUT/'batches').glob('*/validation.json'))),'independent_evaluation':False})

def run_batches(limit=None):
    events,contexts,repairs=verified_events();es={e['modification_id']:e for e in events}
    if not (OUT/'span_corrections.jsonl').exists():lines(OUT/'span_corrections.jsonl',repairs)
    ev,links=sources();ev,links=supplemental(ev,links,events)
    gs=read(OUT/'commit_groups.jsonl');gm={mid:g for g in gs for mid in g['event_ids']}
    (OUT/'batches').mkdir(exist_ok=True)
    if not (OUT/'protocol.json').exists():
        exclusive_json(OUT/'protocol.json',{'version':1,'at':now(),'review_state_separate':True,'pending_status':None,
          'rule_digest':sha(ROOT/'scripts/motive_completion_decisions.py'),'batch_size':50,'dedup_key':'unchanged inherited modification_id',
          'review_method':'assistant-guided conservative scoped review + per-event exact code checks; not human gold or independent evaluation',
          'unknown_allowed_after':'actual event/context review with specific uncertainty, not merely missing annotation',
          'non_exhaustive_material_scope':'All stored sources indexed; assistant reads commit/PR summaries and relevant excerpts. Unknown is epistemic uncertainty within inspected material, not proof no purpose exists.',
          'does_not_change':'stage1, stage2, Agent brands, attribution, source events or old deliveries'})
        lines(OUT/'group_review_notes.jsonl',[{'group_number':g['group_number'],'repository':g['repository'],'modification_sha':g['modification_sha'],
          'event_ids':g['event_ids'],'commit_title':g['title'],'source_ids':g['source_ids'],'note':GROUP_NOTES.get(g['group_number'],'提交上下文已审读；逐事件核验代码和适用目的，缺乏对应则保守记录 unknown。'),
          'review_scope':'commit/PR context plus targeted associated passages, not full-text independent human reading','at':now()} for g in gs])
    if not (OUT/'batches/000_prior_audit/validation.json').exists():
        old=read(OLD/'delivery_v2/annotations.jsonl');audited=[];audit=[]
        for a0 in old:
            a=copy.deepcopy(a0);e=es[a['modification_id']];a.update(review_state='assistant_reviewed',audit_at=now(),batch_id='000_prior_audit',audit_target_observation=e['current_observation'])
            a['audit_result']='exact source quote/link rechecked; stated purpose and inference reread; line-scoped target checked'
            if a['status']=='explicit':assert e['current_observation']['classification']=='target_lines_changed'
            audited.append(a);audit.append({'modification_id':a['modification_id'],'previous_status':a0['status'],'current_status':a['status'],
               'changed':False,'quote_link_check':'PASS','target_span_classification':e['current_observation']['classification']})
        receipt=batch_validate(audited,es,ev,links);bd=OUT/'batches/000_prior_audit';bd.mkdir(exist_ok=True)
        lines(bd/'annotations.jsonl',audited);lines(bd/'audit.jsonl',audit);write(bd/'validation.json',receipt)
        save_progress(audited);print('prior audit',len(audited),'PASS',flush=True)
    aa=load_batches();done={a['modification_id'] for a in aa}
    # Fixed, reproducible queue prioritizes directly applicable evidence, then
    # broader context, then missing target correspondence. Never rereview done IDs.
    prepared=[]
    for e in events:
        if e['modification_id'] in done:continue
        a=annotate(e,gm[e['modification_id']],contexts[e['modification_id']],ev,links)
        priority=(0 if a['status']!='unknown' else 2 if e['current_observation']['classification']=='no_target_span_in_attached_diff' else 1)
        prepared.append((priority,a['group_number'],e['modification_id'],a))
    prepared.sort(key=lambda x:x[:3]);batchno=max([int(p.name.split('_')[0]) for p in (OUT/'batches').iterdir() if p.is_dir()]+[0])+1
    completed=0
    while prepared and (limit is None or completed<limit):
        chunk=prepared[:50];prepared=prepared[50:];bd=OUT/'batches'/f'{batchno:03d}_review';bd.mkdir(exist_ok=False)
        annotations=[dict(x[3],batch_id=bd.name) for x in chunk]
        receipt=batch_validate(annotations,es,ev,links)
        lines(bd/'annotations.jsonl',annotations);lines(bd/'event_checks.jsonl',[{'modification_id':a['modification_id'],'scope_checks':a['scope_checks'],
            'current_observation':es[a['modification_id']]['current_observation']} for a in annotations]);write(bd/'validation.json',receipt)
        aa+=annotations;save_progress(aa);print(bd.name,len(annotations),'PASS','reviewed',len(aa),'pending',1757-len(aa),flush=True)
        completed+=1;batchno+=1
    return aa

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('command',choices=['initialize','show','run']);ap.add_argument('--start',type=int,default=1);ap.add_argument('--end',type=int,default=20);ap.add_argument('--limit-batches',type=int);args=ap.parse_args()
    if args.command=='initialize':initialize()
    elif args.command=='show':show_groups(args.start,args.end)
    else:run_batches(args.limit_batches)
