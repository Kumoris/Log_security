"""Versioned, log-centred DFG slices over existing historical AST witnesses.

Value edges, type/schema evidence and unresolved dependencies are separate.
This is a supplementary static graph, not a new sensitivity or leak verdict.
"""
from __future__ import annotations

import ast
from collections import Counter, defaultdict, deque
import html
import json
from pathlib import Path
import re

from .config import now, sha256_file
from .export import write_json, write_jsonl, write_csv
from .semantic_context import HistoricalContext, load_run, identifier
from .semantic_evidence import analyze_use, digest, loc
from .semantic_ast import IDENTIFIERS
from .storage import stable_id

VERSION = 'dfg-slice-3'
METADATA = {'contract','nominal','definition','vocabulary','schema_document_binding','model'}
PARAMETERS = {'parameter','model_parameter'}
CALLS = {'one_hop','call'}


class Slice:
    def __init__(self, context, max_nodes):
        self.ctx=context;self.limit=max_nodes;self.nodes={};self.edges={};self.functions={}
        self.gaps=[];self.pruned=0
        self.parameter_requests={};self.caller_evidence=[];self.caller_searches=[]

    def function(self, anchor):
        n=self.ctx.node(anchor);p=anchor['path']
        if n is None or isinstance(n,dict):return None
        if anchor.get('parser'):
            s=self.ctx.syntax[p];fn=s.function(n)
            a=s.anchor(fn) if fn else None
            name=s.text(fn.child_by_field_name('name')) if fn else '<module>'
            args=fn.child_by_field_name('parameters') if fn else None
            parameters=[s.anchor(q) for q in args.named_children] if args else []
            returns=[s.anchor(q) for q in s.nodes if q.type=='return_statement' and s.function(q)==fn] if fn else []
            imports=[s.anchor(q) for q in s.root.named_children if q.type in {'import_statement','import_declaration'}]
        else:
            name=self.ctx.python.symbol(p,n);fn=self.ctx.python.functions.get((p,name))
            a=loc(p,fn) if fn else None
            parameters=[loc(p,q) for q in (*fn.args.posonlyargs,*fn.args.args,*fn.args.kwonlyargs)] if fn else []
            returns=[loc(p,q) for q in ast.walk(fn) if isinstance(q,ast.Return) and self.ctx.python.symbol(p,q)==name] if fn else []
            imports=[loc(p,q) for q in self.ctx.python.trees[p].body if isinstance(q,(ast.Import,ast.ImportFrom))]
        uid=stable_id(self.ctx.result['repository'],self.ctx.sha,p,a,name)
        if uid not in self.functions:
            # A per-function index of queried slices; not a whole-codebase DFG.
            self.functions[uid]={'id':uid,'repository':self.ctx.result['repository'],'sha':self.ctx.sha,
                'path':p,'anchor':a,'name':name if identifier(name) or name=='<module>' else '<scoped function>',
                'parameter_anchors':parameters,'return_anchors':returns,'import_anchors':imports,
                'scope':'queried_log_backward_slices_only','node_ids':[]}
        return uid

    def node(self, kind, anchor=None, stack=(), *, endpoint=None, reason=None):
        uid=stable_id(self.ctx.case['id'],kind,anchor,stack)
        if uid in self.nodes:return uid
        if len(self.nodes)>=self.limit:
            uid='truncated';self.gaps.append('graph_node_budget_exceeded')
            self.nodes.setdefault(uid,{'id':uid,'kind':'unresolved','endpoint':'budget_boundary',
                'sha':self.ctx.sha,'anchor':None,'function_id':None,'reason':'graph_node_budget_exceeded'})
            return uid
        evidence=self.ctx.block(anchor,'dfg_'+kind) if anchor else None
        if anchor and evidence is None:raise ValueError('dfg_anchor_missing_from_historical_source')
        if evidence:
            evidence['code_view_truncated']=len(evidence['code_view'])>1200
            evidence['code_view']=evidence['code_view'][:1200]
        function=self.function(anchor) if anchor else None
        self.nodes[uid]={'id':uid,'kind':kind,'anchor':anchor,'sha':self.ctx.sha,'function_id':function,
            'call_context':list(stack),'endpoint':endpoint,'reason':reason,'evidence':evidence,
            'sensitivity':'not_assessed','human_confirmed':False}
        if function:self.functions[function]['node_ids'].append(uid)
        return uid

    def edge(self, source, target, kind, status='structural_ast'):
        if source is None or target is None or source==target:return
        item={'source':source,'target':target,'kind':kind,'status':status,
              'carries_value':kind not in {'metadata','call_argument_dependency'},'runtime_verified':False}
        item['id']=stable_id(item);self.edges[item['id']]=item

    def formal(self, anchor):
        n=self.ctx.node(anchor);p=anchor['path']
        if anchor.get('parser'):
            s=self.ctx.syntax[p];fn=s.function(n)
            if n.type not in IDENTIFIERS or not fn:return None
            args=fn.child_by_field_name('parameters')
            for arg in args.named_children if args else []:
                names=arg.children_by_field_name('name') or [arg.child_by_field_name('pattern') or arg]
                if any(s.text(a)==s.text(n) for a in names):return s.anchor(arg)
        elif isinstance(n,ast.Name):
            fn=self.ctx.python.functions.get((p,self.ctx.python.symbol(p,n)))
            if fn:
                for arg in (*fn.args.posonlyargs,*fn.args.args,*fn.args.kwonlyargs):
                    if arg.arg==n.id:return loc(p,arg)
        return None

    def visit(self, proof, stack=(), selector=None):
        if not proof:return self.node('unresolved',reason='no_ast_witness',endpoint='unknown')
        a=proof.get('anchor');op=proof['op']
        if a and (proof.get('sha')!=self.ctx.sha or proof.get('source_sha256')!=digest(self.ctx.files[a['path']]) or proof.get('snippet_sha256')!=digest(self.ctx.raw(a) or '')):
            raise ValueError('dfg_witness_version_or_hash_mismatch')
        kind='metadata' if op in METADATA else 'unresolved' if op=='unknown' else op
        endpoint='constant' if op in {'literal','fixed_boolean_null'} else None
        uid=self.node(kind,a,stack,endpoint=endpoint,reason=proof.get('reason'))
        if uid=='truncated':return uid
        children=proof.get('children',[])
        if op in PARAMETERS or (op=='unknown' and proof.get('reason') in {'unresolved_binding','unresolved_scoped_binding'}):
            formal=self.formal(a) if a else None
            if formal:
                name=self.ctx.raw(a)
                parent=self.node('parameter_input',formal,stack+(stable_id(name,selector),),endpoint='function_parameter',reason='caller_origin_not_traced')
                if parent!='truncated':self.parameter_requests[parent]={'name':name,'selector':selector}
                self.edge(parent,uid,'parameter_use')
                self.nodes[uid]['kind']='parameter_use'
                self.gaps.append('caller_origin_not_traced')
            else:
                self.nodes[uid]['endpoint']='unknown';self.gaps.append('parameter_binding_unavailable')
            for child in children:self.edge(self.visit(child,stack),uid,'metadata')
            return uid
        if op in METADATA:
            for child in children:self.edge(self.visit(child,stack),uid,'metadata')
            # A semantic contract can stop the old extractor before value origin.
            self.gaps.append('semantic_evidence_is_not_value_origin')
            return uid
        if op in CALLS and children:
            frame=stack+(stable_id(a),)
            value=self.visit(children[0],frame,selector)
            ret=proof.get('return_anchor')
            if ret is None:
                n=self.ctx.node(children[0].get('anchor',{}));s=self.ctx.syntax.get(children[0].get('anchor',{}).get('path'))
                parent=n.parent if s and n else None
                while parent and parent.type!='return_statement':parent=parent.parent
                ret=s.anchor(parent) if parent else None
            returned=self.node('return_value',ret,frame)
            self.edge(value,returned,'return_value')
            self.edge(returned,uid,'call_return','possible' if op=='call' else 'structural_ast')
            if op=='call':self.gaps.append('interprocedural_ast_binding_requires_review')
            return uid
        if op in {'bound_parameter','bound'} and children:
            formal=self.formal(a) if a else None
            actual=self.visit(children[0],stack[:-1],selector)
            if formal:
                param=self.node('bound_formal',formal,stack)
                self.edge(actual,param,'actual_to_formal','possible' if op=='bound' else 'structural_ast')
                self.edge(param,uid,'parameter_use')
            else:
                self.edge(actual,uid,'possible_binding','possible');self.gaps.append('formal_anchor_missing')
            return uid
        if op=='projection' and children:
            value=self.visit(children[0],stack,proof['field'])
            self.edge(value,uid,'field_read');return uid
        if selector is not None and op=='object':
            matches=[i for i,key in enumerate(proof['fields']) if key==selector]
            if matches and None not in proof['fields']:
                self.pruned+=len(children)-1;children=[children[matches[-1]]]
            else:self.gaps.append('projection_selection_unresolved')
        if selector is not None and op=='write':
            self.pruned+=1
            if proof['field']==selector:children=[children[1]];selector=None
            else:children=[children[0]]
        if op=='unknown':
            self.gaps.append(proof.get('reason','unknown_operation'))
            self.nodes[uid]['endpoint']='unknown'
            # Syntax shows consumed expressions, not how an external call's
            # result was computed. Keep these edges explicitly unresolved.
            n=self.ctx.node(a) if a else None
            args=n.args if isinstance(n,ast.Call) else []
            if a and a.get('parser') and n and n.type in {'call_expression','method_invocation'}:
                arguments=n.child_by_field_name('arguments');args=arguments.named_children if arguments else []
            for arg in args:
                aa=self.ctx.syntax[a['path']].anchor(arg) if a.get('parser') else loc(a['path'],arg)
                arg_id=self.node('unresolved_argument',aa,stack,endpoint='unknown')
                self.edge(arg_id,uid,'call_argument_dependency','possible')
            return uid
        values=[self.visit(child,stack,selector if op in {'alias','write','transparent','await_value','branch_merge'} else None) for child in children]
        if op in {'alias','unpack'} and proof.get('definition'):
            definition=self.node('assignment',proof['definition'],stack)
            for v in values:self.edge(v,definition,'assignment')
            self.edge(definition,uid,'reaching_definition')
        else:
            for v in values:self.edge(v,uid,op,'possible' if op in {'alternatives','serialization','branch_merge'} else 'structural_ast')
        if op=='branch_merge':
            condition=self.node('branch_condition',proof['condition'],stack)
            self.edge(condition,uid,'metadata');self.gaps.append('conditional_path_feasibility_unverified')
        return uid

    def reachable(self, root):
        incoming=defaultdict(list)
        for edge in self.edges.values():
            if edge['carries_value']:incoming[edge['target']].append(edge['source'])
        seen=set();todo=[root]
        while todo:
            n=todo.pop()
            if n not in seen:seen.add(n);todo.extend(incoming[n])
        return seen

    def expand_callers(self, root, *, max_chars, max_hops, max_caller_hops):
        from .semantic_callers import caller_arguments
        visited=set();ancestry={};used=0;calls=0
        for depth in range(max_caller_hops):
            pending=[n for n in self.reachable(root) if n in self.parameter_requests and n not in visited]
            for uid in sorted(pending):
                visited.add(uid);node=self.nodes[uid];request=self.parameter_requests[uid]
                chain=ancestry.get(uid,())
                if node['function_id'] in chain:
                    self.gaps.append('recursive_caller_boundary');continue
                if calls>=8 or used>=max_chars or 'truncated' in self.nodes:
                    self.gaps.append('caller_expansion_budget_exceeded');continue
                found,gaps,files=caller_arguments(self.ctx,node['anchor'],request['name'])
                self.gaps.extend(gaps)
                self.caller_searches.append({'parameter_node':uid,'resolved_calls':len(found),'files_examined':files,
                                            'depth':depth+1,'gaps':gaps,'all_callers_proven':False})
                if len(found)>8-calls:self.gaps.append('caller_callsite_budget_exceeded')
                for binding in found[:8-calls]:
                    if used>=max_chars or 'truncated' in self.nodes:
                        self.gaps.append('caller_expansion_budget_exceeded');break
                    a=binding['actual_anchor'];context=(stable_id(uid,binding['call_anchor']),)
                    analysis=analyze_use(self.ctx.files,self.ctx.result['repository'],self.ctx.sha,a['path'],a,
                                         max_chars=max_chars-used,max_hops=max_hops)
                    used+=analysis.get('context_chars',0);calls+=1;before=set(self.parameter_requests)
                    actual=self.visit(analysis['proof'],context,request['selector'])
                    if actual=='truncated':
                        self.gaps.append('caller_expansion_budget_exceeded');break
                    if self.nodes[actual]['kind']=='metadata':
                        value=self.node('unresolved_actual',a,context,endpoint='unknown',reason='semantic_contract_does_not_trace_value')
                        self.edge(actual,value,'metadata');actual=value
                    call=self.node('caller_argument',a,context)
                    if call=='truncated':
                        self.gaps.append('caller_expansion_budget_exceeded');break
                    self.edge(actual,call,'argument_value')
                    self.edge(call,uid,'caller_actual_to_formal',binding['status'])
                    # The snapshot can omit callers or callback registrations. Keep that boundary.
                    node['reason']='additional_callers_not_excluded'
                    for child in set(self.parameter_requests)-before:
                        ancestry[child]=chain+(node['function_id'],)
                    self.gaps.extend(analysis.get('gaps',[]))
                    callsite=self.ctx.block(binding['call_anchor'],'resolved_caller')
                    callsite['code_view_truncated']=len(callsite['code_view'])>1200
                    callsite['code_view']=callsite['code_view'][:1200]
                    self.caller_evidence.append({**binding,'id':stable_id(uid,binding),'parameter_node':uid,
                        'caller_argument_node':call,'sha':self.ctx.sha,'depth':depth+1,
                        'callsite_evidence':callsite,
                        'actual_argument_semantics':analysis['review'],'semantic_scope':'caller_actual_argument_only',
                        'projection_applied':request['selector'] is not None,'log_type_inference':'not_performed',
                        'target_human_confirmed':False,'runtime_verified':False})
        if any(n not in visited for n in self.reachable(root) if n in self.parameter_requests) and max_caller_hops:
            self.gaps.append('caller_depth_budget_exceeded')


def build_graph(ctx, *, max_nodes=200, max_chars=24000, max_hops=2, max_caller_hops=2):
    initial=ctx.initial(max_chars)
    if initial['status'] not in {'success','truncated'}:raise ValueError('dfg_'+initial['status'])
    p=ctx.result['path']
    analysis=analyze_use(ctx.files,ctx.result['repository'],ctx.sha,p,ctx.result['use_anchor'],max_chars=max_chars,max_hops=max_hops)
    graph=Slice(ctx,max_nodes);root=graph.visit(analysis['proof'])
    if graph.nodes[root]['kind']=='metadata':
        value=graph.node('unresolved_use',ctx.result['use_anchor'],endpoint='unknown',reason='semantic_contract_does_not_trace_value')
        graph.edge(root,value,'metadata');root=value
    graph.expand_callers(root,max_chars=max(0,max_chars-analysis.get('context_chars',0)),
                         max_hops=max_hops,max_caller_hops=max_caller_hops)
    field_bindings=[]
    if p.endswith('.go'):
        from .semantic_go import field_binding
        for n in list(graph.nodes.values()):
            if not n.get('anchor') or n['anchor'].get('node_kind')!='selector_expression':continue
            binding=field_binding(ctx,n['anchor'])
            if binding:
                field_bindings.append(binding)
                for key in ('receiver_declaration','type_definition','field_definition','import_anchor'):
                    if binding.get(key):graph.edge(graph.node('metadata',binding[key]),n['id'],'metadata')
                if binding['status']!='bound':graph.gaps.append(binding['reason'])
    log=next(b for b in ctx.blocks if b['kind']=='complete_log_statement')
    sink=graph.node('log_statement',log['anchor'])
    control_context=[]
    use=ctx.node(ctx.result['use_anchor'])
    if p.endswith('.py'):
        from .semantic_flow import controls
        context=[(type(n).__name__,arm,loc(p,getattr(n,'test',None) or getattr(n,'iter',None) or n))
                 for n,arm in controls(ctx.python,p,use)]
    else:
        from .semantic_ast import CONTROL,FUNCTIONS
        context=[];child=use;parent=use.parent
        while parent is not None and parent.type not in FUNCTIONS:
            if parent.type in CONTROL:
                arm=next((parent.field_name_for_child(i) for i,c in enumerate(parent.children) if c==child),None)
                a=ctx.syntax[p].anchor(parent.child_by_field_name('condition') or parent)
                context.append((parent.type,arm,a))
            child=parent;parent=parent.parent
    if len(context)>8:graph.gaps.append('control_context_budget_exceeded')
    for construct,arm,a in context[:8]:
        condition=graph.node('control_condition',a)
        graph.edge(condition,sink,'metadata')
        control_context.append({'construct':construct,'arm':arm,'anchor':a,'node_id':condition,'feasibility':'not_evaluated'})
    relation=ctx.log_relation()
    graph.edge(root,sink,'log_argument' if ctx.result.get('use_role')!='nested_expression_input' else 'nested_log_dependency',
               'structural_ast' if ctx.result.get('use_role')!='nested_expression_input' else 'possible')
    # Only value edges count toward origin reachability; type evidence stays separate.
    incoming=defaultdict(list)
    for e in graph.edges.values():
        if e['carries_value']:incoming[e['target']].append(e['source'])
    reachable=set();todo=[sink]
    while todo:
        n=todo.pop()
        if n in reachable:continue
        reachable.add(n);todo.extend(incoming[n])
    endpoints=[n for n in graph.nodes.values() if n['id'] in reachable and n.get('endpoint')]
    gaps=set(graph.gaps+analysis.get('gaps',[]))
    if graph.caller_evidence:
        gaps.add('additional_callers_not_excluded')
        if all(graph.nodes[n]['reason']!='caller_origin_not_traced' for n in graph.parameter_requests):
            gaps.discard('caller_origin_not_traced')
    if initial['status']=='truncated':gaps.add('initial_context_truncated')
    if ctx.snapshot.get('gaps'):gaps.add('historical_snapshot_has_gaps')
    return {'id':ctx.case['id'],'version':VERSION,'repository':ctx.result['repository'],'sha':ctx.sha,
        'path':p,'field':ctx.result['field'],'side':ctx.result.get('side'),'history_event_id':ctx.case.get('history_event_id'),
        'root_use':root,'log_node':sink,'nodes':list(graph.nodes.values()),'edges':list(graph.edges.values()),
        'functions':list(graph.functions.values()),'origin_frontier':[n['id'] for n in endpoints],
        'origin_counts':dict(Counter(n['endpoint'] for n in endpoints)),
        'pruned_object_branches':graph.pruned,'gaps':sorted(gaps),'log_relation':relation,
        'caller_evidence':graph.caller_evidence,'caller_searches':graph.caller_searches,
        'field_bindings':field_bindings,
        'control_context':control_context,
        'semantic_review_status':analysis['review']['status'],'source_scope':'bounded_static_backward_slice',
        'complete_external_origin':False,'runtime_verified':False,'human_confirmed':False,
        'sensitivity_verdict_changed':False,'input_independent_output':analysis.get('transformation',{}),
        'budgets':{'max_nodes':max_nodes,'budget_sentinel_extra_nodes':int('truncated' in graph.nodes),
                   'max_chars':max_chars,'max_hops':max_hops,'max_caller_hops':max_caller_hops,
                   'max_caller_calls':8,'max_caller_files_per_search':64},'method':'historical_AST_witnesses_and_formal_parameter_bindings'}


def svg(graph):
    """Small layered SVG; no graph service, executable source, or remote fonts."""
    nodes={n['id']:n for n in graph['nodes']};ins=defaultdict(int);out=defaultdict(list)
    for e in graph['edges']:ins[e['target']]+=1;out[e['source']].append(e['target'])
    ranks={k:0 for k in nodes};todo=deque(k for k in nodes if not ins[k]);visited=set()
    while todo:
        k=todo.popleft();visited.add(k)
        for other in out[k]:
            ranks[other]=max(ranks[other],ranks[k]+1);ins[other]-=1
            if ins[other]==0:todo.append(other)
    for k in nodes:
        if k not in visited:ranks[k]=0
    levels=defaultdict(list)
    for k,rank in ranks.items():levels[rank].append(k)
    positions={k:(24+rank*270,30+i*120) for rank,group in levels.items() for i,k in enumerate(group)}
    width=max(x for x,y in positions.values())+250;height=max(y for x,y in positions.values())+116
    content=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img" aria-label="Historical data flow graph">',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="#62758b"/></marker></defs>']
    for e in graph['edges']:
        x,y=positions[e['source']];xx,yy=positions[e['target']];y+=40;yy+=40
        dash='stroke-dasharray="5 4"' if e['kind']=='metadata' or e['status']=='possible' else ''
        content.append(f'<path d="M{x+220},{y} C{x+248},{y} {xx-20},{yy} {xx},{yy}" fill="none" stroke="#62758b" {dash} marker-end="url(#arrow)"><title>{html.escape(e["kind"]+": "+e["status"])}</title></path>')
    for k,n in nodes.items():
        x,y=positions[k];a=n.get('anchor') or {};e=n.get('evidence') or {}
        color='#eff6ff' if n['kind']=='metadata' else '#fff4d7' if n['kind'].startswith('unresolved') or n.get('endpoint') in {'unknown','budget_boundary','function_parameter'} else '#edf9f0'
        label=e.get('code_view','').replace('\n',' ')[:32]
        title=html.escape(json.dumps({key:n.get(key) for key in ('kind','anchor','sha','reason','endpoint')},ensure_ascii=False))
        content.append(f'<g><title>{title}</title><rect x="{x}" y="{y}" width="220" height="84" rx="9" fill="{color}" stroke="#8293a7"/>')
        for offset,text in [(20,n['kind']),(42,label),(65,Path(a.get('path','')).name+':'+str(a.get('line','?')))]:
            text=text if len(text)<=29 else text[:26]+'...'
            content.append(f'<text x="{x+10}" y="{y+offset}" font-family="monospace" font-size="11" fill="#15283f">{html.escape(text)}</text>')
        content.append('</g>')
    return ''.join(content)+'</svg>'


def export_dfg(run, output, options=None, *, dry_run=False, resume=False, max_cases=20):
    options={'max_nodes':200,'max_chars':24000,'max_hops':2,'max_caller_hops':2,**(options or {})}
    for key,ceiling in [('max_nodes',1000),('max_chars',48000),('max_hops',4)]:
        if type(options[key]) is not int or not 1<=options[key]<=ceiling:raise ValueError('invalid_dfg_budget:'+key)
    if type(options['max_caller_hops']) is not int or not 0<=options['max_caller_hops']<=4:raise ValueError('invalid_dfg_budget:max_caller_hops')
    if type(max_cases) is not int or not 1<=max_cases<=100:raise ValueError('dfg_case_budget_1_to_100')
    if dry_run:return {'status':'dry_run','files_written':False,'model_calls':0,'max_cases':max_cases,'exit_code':0}
    run=Path(run);output=Path(output);cases,snapshots,manifest=load_run(run)
    if any(not re.fullmatch('[0-9a-f]{24}',key) or case.get('id')!=key for key,case in cases.items()):
        raise ValueError('dfg_requires_canonical_frozen_case_ids')
    fingerprint={'input_manifest':sha256_file(run/'manifest.json'),'checkpoint':sha256_file(run/'checkpoint.sqlite'),
        'options':options,'max_cases':max_cases,'sources':{p.name:sha256_file(p) for p in sorted(Path(__file__).parent.glob('*.py'))}}
    if output.exists() and any(output.iterdir()):
        old=json.loads((output/'manifest.json').read_text())
        if not resume or old['fingerprint']!=fingerprint:raise ValueError('dfg_input_or_code_changed_use_new_output')
        if any(sha256_file(output/p)!=h for p,h in old['artifact_sha256'].items()):raise ValueError('dfg_output_integrity_mismatch')
        return {**json.loads((output/'coverage.json').read_text()),'resumed_without_reprocessing':True}
    chosen=sorted(cases)[:max_cases];graphs=[];errors=[]
    for key in chosen:
        case=cases[key];r=case['result'];raw=snapshots.get((r['repository'],r['sha']))
        try:
            if raw is None:raise ValueError('historical_snapshot_missing')
            if not r.get('use_anchor'):raise ValueError('use_anchor_missing')
            ctx=HistoricalContext(case,raw);graph=build_graph(ctx,**options)
            write_json(output/'graphs'/(key+'.json'),graph)
            (output/'graphs'/(key+'.svg')).write_text(svg(graph))
            graphs.append(graph)
        except (ValueError,KeyError,SyntaxError,RecursionError) as exc:
            errors.append({'id':key,'status':'unresolved','reason':str(exc) if isinstance(exc,ValueError) else type(exc).__name__})
    nodes=[dict(n,case_id=g['id']) for g in graphs for n in g['nodes']]
    edges=[dict(e,case_id=g['id']) for g in graphs for e in g['edges']]
    functions={}
    for g in graphs:
        for f in g['functions']:
            row=functions.setdefault(f['id'],{**f,'node_ids':[],'case_ids':[]})
            row['node_ids']=sorted(set(row['node_ids']+f['node_ids']));row['case_ids'].append(g['id'])
    for name,rows in {'nodes':nodes,'edges':edges,'functions':list(functions.values()),'unresolved_cases':errors,
                     'caller_evidence':[dict(c,case_id=g['id']) for g in graphs for c in g['caller_evidence']],
                     'field_bindings':[dict(c,case_id=g['id']) for g in graphs for c in g['field_bindings']],
                     'not_selected':[{'id':i,'reason':'case_budget'} for i in sorted(cases) if i not in chosen]}.items():
        write_jsonl(output/(name+'.jsonl'),rows);write_csv(output/(name+'.csv'),rows)
    summaries=[{k:g[k] for k in ('id','repository','sha','path','field','side','origin_counts','gaps','semantic_review_status')} for g in graphs]
    write_jsonl(output/'source_summaries.jsonl',summaries);write_csv(output/'source_summaries.csv',summaries)
    report={'status':'complete_with_declared_gaps','exit_code':0,'input_cases':len(cases),'selected_cases':len(chosen),
        'graphs':len(graphs),'unresolved_cases':len(errors),'node_records':len(nodes),'edge_records':len(edges),'functions':len(functions),
        'origin_frontiers':dict(sum((Counter(g['origin_counts']) for g in graphs),Counter())),
        'cases_with_parameter_frontier':sum(bool(g['origin_counts'].get('function_parameter')) for g in graphs),
        'cases_with_unknown_frontier':sum(bool(g['origin_counts'].get('unknown')) for g in graphs),
        'cases_with_resolved_callers':sum(bool(g['caller_evidence']) for g in graphs),
        'resolved_caller_bindings':sum(len(g['caller_evidence']) for g in graphs),
        'cases_with_bound_field_definitions':sum(any(b['status']=='bound' for b in g['field_bindings']) for g in graphs),
        'gaps_by_case':dict(Counter(gap for g in graphs for gap in g['gaps'])),
        'graphs_by_repository':dict(Counter(g['repository'] for g in graphs)),
        'graphs_by_extension':dict(Counter(Path(g['path']).suffix for g in graphs)),
        'semantic_accuracy':None,'complete_source_recall':None,'human_annotations':0,'model_calls':0,'target_code_executed':False,
        'input_sensitivity_verdicts_unchanged':True,'history_source':'existing_PyDriller_mined_exact_revision_checkpoints',
        'function_index_scope':'selected_use_backward_slices_not_all_functions','case_selection':'sorted_frozen_case_id_budget',
        'method_reference':'10.1145/3603719.3603734 sections 1.2, 2.2, 2.3; bounded adaptation, not a reproduction'}
    write_json(output/'coverage.json',report)
    cards=[]
    for g in sorted(graphs,key=lambda g:-len(g['edges'])):
        title=html.escape(g['repository']+' · '+g['field']+' · '+g['sha'][:10])
        cards.append(f'<details><summary>{title}</summary><p>{html.escape(g["path"])}</p><p>来源边界：{html.escape(json.dumps(g["origin_counts"]))}</p><div class="graph">{svg(g)}</div><p><a href="graphs/{g["id"]}.json">完整节点、边与历史证据</a></p></details>')
    (output/'index.html').write_text('<!doctype html><meta charset="utf-8"><title>历史数据来源 DFG</title><style>body{font:16px system-ui;margin:32px;color:#15283f;background:#f6f8fb}details{background:white;padding:20px;margin:14px 0;border:1px solid #d8e0e9;border-radius:12px}summary{cursor:pointer;font-weight:600}.graph{overflow:auto}a{color:#155f9f}</style><h1>历史数据来源 DFG</h1><p>箭头从产生值的位置指向使用位置。虚线表示元数据关系或不确定依赖；悬停查看边类型和源码锚点。蓝色为元数据，黄色为参数边界或未知，绿色为局部结构。</p><p>这是辅助静态证据：参数不等于最终数据源，类型不等于值传播，图不证明执行路径、敏感性或运行时泄露。完整结果仍需人工核对。</p>'+''.join(cards))
    write_json(output/'manifest.json',{'status':'complete','created_at':now(),'version':VERSION,'fingerprint':fingerprint,
        'artifact_sha256':{str(p.relative_to(output)):sha256_file(p) for p in output.rglob('*') if p.is_file() and p.name!='manifest.json'}})
    return report
