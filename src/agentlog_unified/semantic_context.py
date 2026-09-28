"""Historical, anchor-bound context retrieval and finite static checks.

No model string is a filesystem path. Sources come only from a verified mining
checkpoint; absent objects are reported, never replaced by a working tree.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import sqlite3

from .config import sha256_file
from .detector import PythonSnapshot, _name, _snippet
from .semantic_evidence import analyze_use, digest, loc, node_at, review, verified_import
from .semantic_ast import Syntax, FUNCTIONS, IDENTIFIERS, view as tree_view
from .storage import stable_id

VERSION = 'demand-context-1'
KINDS = ('symbol_definition', 'function_binding', 'object_fields', 'bound_schema',
         'referenced_document', 'flow_edge')
SCHEMA_KEYS = {'type', 'format', 'properties', 'items', 'required', '$defs', '$ref',
               'definitions', 'allOf', 'anyOf', 'oneOf', 'additionalProperties'}
SCHEMA_VALUES = {'object', 'array', 'string', 'integer', 'number', 'boolean', 'null',
                 'email', 'ipv4', 'ipv6', 'uuid', 'date', 'date-time', 'uri'}


def contains(outer, inner):
    return outer['path']==inner['path'] and (outer['line'],outer.get('column',0)) <= (inner['line'],inner.get('column',0)) and (outer['end_line'],outer.get('end_column',10**9)) >= (inner['end_line'],inner.get('end_column',10**9))
# Only syntactically structural identifiers survive. Free text, even apparently
# benign descriptions, is not allowlisted merely because a secret regex missed it.
def identifier(name):
    return bool(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,47}', name)) and not re.search(r'\d{6}|[A-Z0-9]{20}', name)


def safe_view(source, path):
    removed = {'literal_values': 0, 'comments_and_free_text': True, 'opaque_identifiers': 0}
    if Path(path).suffix == '.py':
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return '<withheld: incomplete Python syntax>', {**removed, 'parse_failed': True}
        parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        # Keys only when they are also bound code identifiers, or grammar keywords.
        bound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        bound |= {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
        bound |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        allowed = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        if k.value in SCHEMA_KEYS or (k.value in bound and identifier(k.value)):
                            allowed.add(id(k))
                        if k.value in {'format', 'type'} and isinstance(v, ast.Constant) and v.value in SCHEMA_VALUES:
                            allowed.add(id(v))
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
                # Only a key corroborated by a declaration is retained.
                if n.slice.value in bound and identifier(n.slice.value): allowed.add(id(n.slice))
        class Hide(ast.NodeTransformer):
            def visit_Constant(self, n):
                if id(n) in allowed: return n
                removed['literal_values'] += 1
                return ast.copy_location(ast.Constant('<withheld:' + type(n.value).__name__ + '>'), n)
            def generic_visit(self, n):
                for key in ('id', 'arg', 'attr', 'name', 'asname', 'module'):
                    value = getattr(n, key, None)
                    if isinstance(value, str) and any(not identifier(v) for v in value.split('.') if v):
                        setattr(n, key, 'withheld_identifier'); removed['opaque_identifiers'] += 1
                return super().generic_visit(n)
        text = ast.unparse(Hide().visit(tree))
    elif Path(path).suffix in {'.json', '.yaml', '.yml'}:
        import yaml
        try:
            obj = json.loads(source) if path.endswith('.json') else yaml.safe_load(source)
            def clean(value, key='', depth=0):
                if depth > 16: return '<withheld: depth>'
                if isinstance(value, dict):
                    return {k if k in SCHEMA_KEYS else 'field_' + digest(str(k))[:10]: clean(v, str(k), depth+1) for k, v in value.items()}
                if isinstance(value, list): return [clean(v, key, depth+1) for v in value[:64]]
                if key in {'type', 'format'} and isinstance(value, str) and value in SCHEMA_VALUES: return value
                removed['literal_values'] += 1
                return '<withheld:' + type(value).__name__ + '>'
            text = json.dumps(clean(obj), ensure_ascii=False)
        except (ValueError, yaml.YAMLError, RecursionError): text = '<withheld: invalid schema>'
    elif Path(path).suffix in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.go', '.java'}:
        text = tree_view(source, path)
        # The existing lexer removes all literals/comments, including object keys.
        s = Syntax(path, text); edits = []
        for n in s.nodes:
            if n.type in IDENTIFIERS and not identifier(s.text(n)):
                edits.append((n.start_byte, n.end_byte)); removed['opaque_identifiers'] += 1
        raw = text.encode()
        for a, b in sorted(edits, reverse=True): raw = raw[:a] + b'withheld_identifier' + raw[b:]
        text = raw.decode(); removed['literal_values'] = 'all_lexer_literals'
    else:
        text = '<withheld: free text; source reference and hash available for local human review>'
    return text, {**removed, 'is_verbatim': False, 'policy': VERSION,
                  'impact': 'literal values, unbound keys and free prose cannot support model claims'}


class HistoricalContext:
    def __init__(self, case, snapshot):
        self.case = case; self.result = case['result']; self.sha = self.result['sha']
        if snapshot.get('sha', self.sha) != self.sha: raise ValueError('historical_snapshot_sha_mismatch')
        self.files = snapshot['files']; self.snapshot = snapshot
        for v in case.get('source_versions', []):
            if v['sha'] != self.sha or v['path'] not in self.files or digest(self.files[v['path']]) != v['source_sha256']:
                raise ValueError('case_source_version_mismatch')
        self.python = PythonSnapshot(self.files); self.syntax = {}
        self.blocks = []; self.requests_seen = set(); self.extra_paths = set(); self.retrievals = []

    def node(self, anchor):
        if not isinstance(anchor, dict) or anchor.get('path') not in self.files: return None
        if anchor.get('parser') == 'tree_sitter':
            p = anchor['path']
            if p not in self.syntax: self.syntax[p] = Syntax(p, self.files[p])
            return self.syntax[p].at(anchor)
        if anchor.get('node_kind') == 'document': return anchor
        return node_at(self.python, anchor)

    def raw(self, anchor):
        n = self.node(anchor)
        if n is None: return None
        p = anchor['path']
        if isinstance(n, dict): return self.files[p]
        return self.syntax[p].text(n) if anchor.get('parser') else _snippet(self.files[p], n)

    def block(self, anchor, kind):
        raw = self.raw(anchor)
        if raw is None: return None
        text, policy = safe_view(raw, anchor['path'])
        provenance = self.snapshot.get('file_provenance', {}).get(anchor['path'])
        return {'id': stable_id(self.result['repository'], self.sha, anchor, digest(raw)),
                'repository': self.result['repository'], 'sha': self.sha, 'anchor': anchor,
                'source_sha256': digest(self.files[anchor['path']]), 'snippet_sha256': digest(raw),
                'code_view': text, 'kind': kind, 'redaction': policy,
                'source_backend': provenance if provenance is not None else self.snapshot.get('backend'),
                'revision_backend': self.snapshot.get('revision_backend'),
                'fallback_reason': provenance.get('fallback_reason') if isinstance(provenance,dict) and 'fallback_reason' in provenance else self.snapshot.get('fallback_reason'),
                'checkpoint_reused': True}

    def add(self, anchor, kind, budget):
        b = self.block(anchor, kind)
        if b is None: return 'not_found'
        if any(v['id'] == b['id'] or contains(v['anchor'],anchor) for v in self.blocks): return 'duplicate'
        if sum(len(v['code_view']) for v in self.blocks) + len(b['code_view']) > budget: return 'truncated'
        self.blocks.append(b); return 'success'

    def initial(self, budget=12000):
        p = self.result['path']; a = self.result['use_anchor']; n = self.node(a)
        if n is None: return {'status': 'context_missing'}
        anchors = []
        if a.get('parser'):
            s = self.syntax[p]; call = n
            while call and not (call.type in {'call_expression','method_invocation'} and call.start_point.row+1 == self.case['log_start_line'] and call.end_point.row+1 == self.case['log_end_line'] and digest(s.text(call)) == self.case['log_statement_sha256']): call = call.parent
            if not call or digest(s.text(call)) != self.case['log_statement_sha256']:return {'status':'log_anchor_mismatch'}
            anchors.append((s.anchor(call), 'complete_log_statement'))
            f = s.function(n)
            if f: anchors.append((s.anchor(f), 'enclosing_function'))
            anchors += [(s.anchor(x), 'import_binding') for x in s.root.named_children if x.type in {'import_statement', 'import_declaration'}]
        else:
            calls = [x for x in ast.walk(self.python.trees[p]) if isinstance(x, ast.Call) and x.lineno == self.case['log_start_line'] and x.end_lineno == self.case['log_end_line'] and digest(_snippet(self.files[p], x)) == self.case['log_statement_sha256']]
            if len(calls) != 1: return {'status': 'log_anchor_mismatch'}
            anchors.append((loc(p, calls[0]), 'complete_log_statement'))
            f = self.python.functions.get((p, self.python.symbol(p, n)))
            if f: anchors.append((loc(p, f), 'enclosing_function'))
            anchors += [(loc(p, x), 'import_binding') for x in self.python.trees[p].body if isinstance(x, (ast.Import, ast.ImportFrom))]
        statuses = [self.add(anchor, kind, budget) for anchor, kind in anchors]
        # Always retain a small exact use expression, even if its function was truncated.
        self.add(a, 'field_use', budget)
        return {'status': 'truncated' if 'truncated' in statuses else 'success', 'statuses': statuses}

    def payload(self):
        return {'case_id': self.case['id'], 'repository': self.result['repository'], 'sha': self.sha,
                'path': self.result['path'], 'scope': self.result['scope'], 'field': self.result['field'],
                'use_anchor': self.result['use_anchor'], 'use_role': self.result.get('use_role'),
                'output_expression_anchor': self.result.get('output_expression_anchor'),
                'blocks': deepcopy(self.blocks), 'context_chars': sum(len(b['code_view']) for b in self.blocks),
                'baseline_rule_gaps_at_prior_run': self.result.get('context', {}).get('gaps', []),
                'fixture_or_tutorial_path': any(x in self.result['path'].lower() for x in ('test', 'fixture', 'example', 'tutorial')),
                'metadata_semantics': 'not_applicable_program_use', 'history_side': self.result.get('side'),
                'history_event_id': self.case.get('history_event_id')}

    def _definitions(self, block, symbol):
        """Only local scope or explicit import/type binding, never global name search."""
        p = block['anchor']['path']; a = block['anchor']; n = self.node(a)
        if a.get('parser'):
            s = self.syntax[p]; names = [x for x in s.nodes if x.start_byte >= n.start_byte and x.end_byte <= n.end_byte and s.text(x) == symbol and x.type in IDENTIFIERS]
            found = []
            for use in names:
                d = s.declarations(use)
                if d: found.append(s.anchor(d[0]))
                for x in s.root.named_children:
                    name = x.child_by_field_name('name')
                    if name and s.text(name) == symbol: found.append(s.anchor(x))
            # Named, relative JS/TS imports. Runtime dispatch and package aliases
            # remain unresolved; this retrieves a definition, not a flow proof.
            if names and p.endswith(('.ts','.tsx','.js','.jsx','.mjs','.cjs')):
                for imp in s.root.named_children:
                    if imp.type!='import_statement':continue
                    module=imp.child_by_field_name('source')
                    if module is None:continue
                    try:relative=ast.literal_eval(s.text(module))
                    except (ValueError,SyntaxError):continue
                    if not isinstance(relative,str) or not relative.startswith('.'):continue
                    for spec in s.nodes:
                        if spec.type!='import_specifier' or not imp.start_byte<=spec.start_byte<imp.end_byte:continue
                        original=spec.child_by_field_name('name');alias=spec.child_by_field_name('alias') or original
                        if alias is None or original is None or s.text(alias)!=symbol:continue
                        base=posixpath.normpath(posixpath.join(posixpath.dirname(p),relative))
                        if base.startswith(('../','/')):continue
                        alternatives={base,base+'.ts',base+'.tsx',base+'.js',base+'/index.ts',base+'/index.js'}
                        if base.endswith('.js'):alternatives.add(base[:-3]+'.ts')
                        targets=sorted(q for q in alternatives if q in self.files)
                        if len(targets)!=1:return [],'relative_import_target_missing_or_ambiguous'
                        tp=targets[0]
                        if tp not in self.syntax:self.syntax[tp]=Syntax(tp,self.files[tp])
                        ts=self.syntax[tp]
                        matches=[x for x in ts.nodes if x.type in FUNCTIONS|{'class_declaration','interface_declaration','type_alias_declaration'} and ts.scope(x)=='<module>' and ts.text(x.child_by_field_name('name'))==s.text(original)]
                        if len(matches)==1:found.append(ts.anchor(matches[0]))
                        elif len(matches)>1:return [],'imported_definition_ambiguous'
            return found, 'cross_module_ast_dispatch_unresolved' if not found else None
        if not isinstance(n, ast.AST): return [], 'non_code_origin'
        occurrences = [x for x in ast.walk(n) if _name(x) == symbol or isinstance(x, ast.arg) and x.arg == symbol]
        if not occurrences: return [], 'symbol_not_bound_at_origin'
        found = []
        for use in occurrences:
            scope = self.python.symbol(p, use); head, _, tail = symbol.partition('.')
            f = self.python.functions.get((p, scope))
            if isinstance(use, ast.Name):
                from .semantic_evidence import exact_assignment
                d = exact_assignment(self.python, p, use)
                if d: found.append(loc(p, d))
            target = self.python.function(p, scope, symbol)
            parameter_names = [] if not f else [x.arg for x in (*f.args.posonlyargs,*f.args.args,*f.args.kwonlyargs)]
            shadowed = head in parameter_names or bool(self.python.assignments.get((p,scope,head)))
            if target and not shadowed and (target[0] == p or verified_import(self.python, p, use, head)):
                found.append(loc(*target))
            model = self.python.model(p, symbol)
            if model and (verified_import(self.python, p, use, head) or model[0] == p): found.append(loc(*model))
            if f:
                arg = next((x for x in (*f.args.posonlyargs, *f.args.args, *f.args.kwonlyargs) if x.arg == head), None)
                if arg and arg.annotation:
                    found.append(loc(p, arg))
                    model = self.python.model(p, _name(arg.annotation))
                    if model:
                        mp, cls = model
                        if tail:
                            found += [loc(mp, x) for x in cls.body if getattr(x, 'name', None) == tail or isinstance(x, ast.AnnAssign) and _name(x.target) == tail]
                        else: found.append(loc(mp, cls))
            if tail:
                # Statically constructed receiver or self in a lexical class.
                from .semantic_evidence import exact_assignment
                receiver = use.value if isinstance(use, ast.Attribute) else None
                model = None
                if isinstance(receiver, ast.Name):
                    d = exact_assignment(self.python, p, receiver)
                    if d and isinstance(d.value, ast.Call) and not self.python.conditional(p,d):
                        model = self.python.model(p,_name(d.value.func))
                    elif head == 'self' and '.' in scope:
                        cls = self.python.classes.get((p,scope.rsplit('.',1)[0]))
                        if cls: model = (p,cls)
                if model:
                    mp, cls = model
                    found += [loc(mp,x) for x in cls.body if getattr(x,'name',None)==tail]
            # Explicit module constants/schema definitions.
            if verified_import(self.python, p, use, head):
                target = self.python.imported(p, head)
                if target:
                    tp, name = target; name = '.'.join(filter(None, (name, tail)))
                    for d in self.python.trees.get(tp, ast.Module(body=[], type_ignores=[])).body:
                        if getattr(d, 'name', None) == name or isinstance(d, (ast.Assign, ast.AnnAssign)) and any(_name(t) == name for t in (d.targets if isinstance(d, ast.Assign) else [d.target])): found.append(loc(tp, d))
            elif not shadowed:
                definitions=self.python.assignments.get((p,'<module>',symbol),[])
                if len(definitions)==1 and definitions[0].lineno<use.lineno and not self.python.conditional(p,definitions[0]):
                    found.append(loc(p,definitions[0]))
        return found, None if found else 'binding_unresolved'

    def retrieve(self, request, *, budget=24000, max_files=8):
        record = {**request, 'request_reason':request.get('reason'), 'sha': self.sha, 'repository': self.result['repository'], 'source_backend': self.snapshot.get('backend'),
                  'revision_backend': self.snapshot.get('revision_backend'), 'fallback_reason': self.snapshot.get('fallback_reason'),
                  'status': 'unsupported', 'reason': None, 'blocks_added': [], 'max_files': max_files, 'max_chars': budget}
        def finish(status, reason=None):
            record.update(status=status, reason=reason, extra_files_used=len(self.extra_paths), context_chars=sum(len(b['code_view']) for b in self.blocks))
            self.retrievals.append(record); return record
        if request.get('case_id') != self.case['id']: return finish('unsupported', 'case_mismatch')
        if request.get('sha', self.sha) != self.sha or request.get('repository', self.result['repository']) != self.result['repository']: return finish('unsupported', 'version_or_repository_mismatch')
        if request.get('request_kind') not in KINDS: return finish('unsupported', 'request_kind_not_allowed')
        symbol = request.get('symbol_or_field', '')
        if not re.fullmatch(r'[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*', symbol) or len(symbol) > 120: return finish('unsupported', 'invalid_symbol_no_paths_or_commands')
        block = next((b for b in self.blocks if b['id'] == request.get('origin_anchor')), None)
        if not block: return finish('unsupported', 'invented_origin_anchor')
        if not '.' in symbol and block['anchor'].get('parser') is None:
            origin=self.node(block['anchor'])
            if isinstance(origin,ast.AST):
                matching={_name(x) for x in ast.walk(origin) if isinstance(x,ast.Attribute) and x.attr==symbol}
                if not any(isinstance(x,ast.Name) and x.id==symbol for x in ast.walk(origin)):
                    if len(matching)>1:return finish('ambiguous','multiple_field_receivers_at_origin')
                    if len(matching)==1:symbol=matching.pop();record['resolved_symbol']=symbol
        key = stable_id(request['request_kind'], block['id'], symbol)
        if key in self.requests_seen: return finish('duplicate', 'duplicate_request')
        self.requests_seen.add(key)
        anchors, gap = self._definitions(block, symbol)
        if request['request_kind'] in {'bound_schema', 'referenced_document'}:
            # Paths are taken exclusively from literal references in anchored code.
            from .semantic_bindings import reference_files
            audit=[]
            referenced = reference_files({**self.files, block['anchor']['path']: self.raw(block['anchor'])}, block['anchor']['path'],audit)
            record['reference_audit']=audit
            if audit and not referenced:gap=gap or audit[0]['reason']
            if not anchors and gap == 'symbol_not_bound_at_origin': return finish('unsupported', gap)
            for p in referenced:
                if p == block['anchor']['path']: continue
                anchors.append({'path': p, 'line': 1, 'end_line': len(self.files[p].splitlines()), 'node_kind': 'document'})
        anchors = list({stable_id(a): a for a in anchors}.values())
        if not anchors: return finish('not_found', gap or 'same_sha_dependency_unavailable')
        outcomes = []
        for a in anchors:
            p = a['path']
            if p not in {b['anchor']['path'] for b in self.blocks} and p not in self.extra_paths:
                if len(self.extra_paths) >= max_files: outcomes.append('truncated'); continue
                self.extra_paths.add(p)
            status = self.add(a, request['request_kind'], budget); outcomes.append(status)
            if status == 'success': record['blocks_added'].append(self.blocks[-1]['id'])
        if 'truncated' in outcomes: return finish('truncated', 'context_or_file_budget')
        if record['blocks_added']: return finish('success', gap)
        return finish('duplicate', 'no_new_evidence')

    def checks(self):
        """Replay raw AST witnesses; visibility gate prevents hidden context claims."""
        r = self.result; steps = []; gaps = []
        anchors_ok = all(b['sha'] == self.sha and b['repository'] == r['repository'] and b['source_sha256'] == digest(self.files[b['anchor']['path']]) and digest(self.raw(b['anchor']) or '') == b['snippet_sha256'] for b in self.blocks)
        visible_files = {b['anchor']['path']: self.files[b['anchor']['path']] for b in self.blocks}
        try:
            analysis = analyze_use(visible_files, r['repository'], self.sha, r['path'], r['use_anchor'], max_chars=24000, max_hops=2)
        except (SyntaxError, ValueError, RecursionError, KeyError):
            analysis = {'proof': None, 'review': {'status': 'ambiguous', 'reasons': ['parser_unsupported']}, 'gaps': ['parser_unsupported']}
        def visit(proof, parent=None):
            if not proof: return
            a = proof.get('anchor'); refs = [b['id'] for b in self.blocks if a and contains(b['anchor'],a)]
            op = proof.get('op'); reason = proof.get('reason')
            if not refs: reason = reason or 'witness_not_in_model_context'
            required=[proof.get(k) for k in ('definition','model','return_anchor') if isinstance(proof.get(k),dict)]
            binding=proof.get('binding',{})
            required += [binding[k] for k in ('binding_anchor','schema_anchor') if isinstance(binding.get(k),dict)]
            required += [r['anchor'] for r in binding.get('references',[]) if r.get('anchor')]
            if any(not any(contains(b['anchor'],w) for b in self.blocks) for w in required):reason=reason or 'witness_not_in_model_context'
            if op in {'unknown', 'alternatives', 'serialization'}: reason = reason or 'dynamic_or_transformation_unresolved'
            steps.append({'id': stable_id(self.case['id'], a, op), 'anchor': a, 'sha': self.sha,
                          'operation': op, 'evidence_refs': refs, 'parent_step': parent,
                          'direction': 'child_value_to_parent_use', 'status': 'unresolved' if reason else 'structural_witness', 'reason': reason,
                          'definition_anchor':proof.get('definition'), 'return_anchor':proof.get('return_anchor'),
                          'actual_to_formal':{k:v.get('anchor') for k,v in proof.get('bindings',{}).items()},
                          'projection_field_hash':digest(str(proof['field'])) if 'field' in proof else None})
            current = steps[-1]['id']
            for child in proof.get('children', []): visit(child, current)
        visit(analysis.get('proof'))
        if any(s['reason']=='witness_not_in_model_context' for s in steps):
            analysis['review']={**analysis['review'],'status':'ambiguous','derived_meanings':[],
                                'reasons':analysis['review'].get('reasons',[])+['witness_not_in_model_context']}
        gaps += analysis.get('gaps', []) + analysis['review'].get('reasons', [])
        log = self.log_relation()
        gaps += log.pop('gaps')
        replay_supported = analysis['review']['status'] == 'supported' and all(s['status'] == 'structural_witness' for s in steps) and bool(steps)
        return {'case_id': self.case['id'], 'field_role':r.get('use_role'), 'anchor_validity': 'valid' if anchors_ok else 'invalid',
                'structural_validity': 'checked_partial_ast', 'supported_flow_validity': 'supported_bounded_static' if replay_supported else 'unresolved',
                'path_feasibility': 'not_proved', 'runtime_validity': 'not_run', 'target_code_executed': False,
                'steps': steps, 'independent_rule_replay': analysis['review'], 'log_relation': log,
                'gaps': sorted(set(gaps)), 'sanitization': analysis.get('transformation', {'status': 'unverified'})}

    def log_relation(self):
        r = self.result; a = r['use_anchor']; n = self.node(a); output_a = r.get('output_expression_anchor') or a; output = self.node(output_a)
        result = {'value': 'unknown', 'evidence_refs': [b['id'] for b in self.blocks if b['kind'] == 'complete_log_statement'], 'gaps': []}
        if n is None or output is None or not result['evidence_refs']: result['gaps'] = ['log_use_anchor_missing']; return result
        if not a.get('parser'):
            statement=next(b for b in self.blocks if b['kind']=='complete_log_statement')
            call=self.node(statement['anchor'])
            sink=self.python.sink(a['path'],call,allow_wrapper=False)
            if sink is None:
                # A wrapper's parameter can be counted, masked or never logged.
                # Passing it to the wrapper is not its concrete output expression.
                return {**result,'value':'possible','statement_kind':'unresolved_wrapper_or_non_sink',
                        'gaps':['wrapper_argument_to_concrete_log_output_unresolved'],'validity':'call_argument_only'}
            result['statement_kind']='recognized_logging_or_stdout_call'
            result['sink_detection_status']=sink[0]
        if a.get('parser'):
            s = self.syntax[a['path']]
            if output == n: result['value'] = 'selected_field' if n.type in {'member_expression','selector_expression','subscript_expression','field_access'} else 'direct_original'
            else: result['value'] = 'possible'; result['gaps'] = ['multilanguage_output_transform_unresolved']
            result['validity'] = 'static_syntax_only'; return result
        if isinstance(output, (ast.Attribute,ast.Subscript)):result['value']='selected_field'
        elif isinstance(output, ast.Call):
            name = _name(output.func)
            unshadowed = name in {'len', 'bool'} and not any(p == a['path'] and key == name for p, scope, key in self.python.assignments) and (a['path'], name) not in self.python.functions and name not in self.python.imports[a['path']]
            f = self.python.functions.get((a['path'], self.python.symbol(a['path'], n)))
            if f and name in [arg.arg for arg in (*f.args.args, *f.args.posonlyargs, *f.args.kwonlyargs)]: unshadowed = False
            if unshadowed and len(output.args) == 1 and (output is n or n in ast.walk(output.args[0])): result['value'] = 'derived_count' if name == 'len' else 'derived_boolean'
            elif name in {'str', 'repr', 'json.dumps', 'asdict', 'dataclasses.asdict'}: result['value'] = 'serialization_formatting'
            else: result['value'] = 'possible'; result['gaps'] = ['output_call_effect_unresolved']
        elif output is n:result['value']='direct_original'
        else: result['value'] = 'possible'; result['gaps'] = ['output_transform_unresolved']
        result['validity'] = 'static_syntax_only'; return result


def merge_snapshot(snapshots, repository, sha, raw):
    """Retain all exact-revision files from overlapping commit checkpoints."""
    if raw.get('sha', sha) != sha:
        raise ValueError('historical_snapshot_sha_mismatch')
    key = (repository, sha)
    prior = snapshots.get(key)
    if prior is None:
        snapshots[key] = {**raw, 'files':dict(raw['files']),
                          'file_provenance':dict(raw.get('file_provenance', {})),
                          'gaps':list(raw.get('gaps', []))}
        return
    if any(prior['files'][p] != source for p, source in raw['files'].items() if p in prior['files']):
        raise ValueError('conflicting_same_revision_snapshot_source')
    prior['files'].update(raw['files'])
    for path, evidence in raw.get('file_provenance', {}).items():
        prior['file_provenance'].setdefault(path, evidence)
    prior['gaps'] = list({stable_id(g):g for g in prior['gaps'] + raw.get('gaps', [])}.values())


def load_run(run):
    run = Path(run); manifest = json.loads((run/'manifest.json').read_text())
    if manifest['status'] != 'complete': raise ValueError('complete_frozen_input_required')
    for name, expected in manifest['artifact_sha256'].items():
        p = PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or sha256_file(run/name) != expected: raise ValueError('input_integrity_mismatch')
    cases = {p.stem: json.loads(p.read_text()) for p in (run/'evidence').glob('*.json')}
    db = sqlite3.connect(f'file:{run.resolve()}/checkpoint.sqlite?mode=ro', uri=True)
    try: units = [json.loads(row[0]) for row in db.execute("SELECT data FROM records WHERE kind='mined_units'")]
    finally: db.close()
    snapshots = {}
    for unit in units:
        for sha, raw in unit['snapshots'].items():
            merge_snapshot(snapshots, unit['repository'], sha, raw)
    return cases, snapshots, manifest
