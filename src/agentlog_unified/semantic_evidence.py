"""Bounded field meanings and independently checked source witnesses; no execution.

Names are proposals only. Supported meanings require literal/annotation/schema or
an exact, repository+module+revision scoped definition and a replayable flow.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import PurePosixPath

from .detector import PythonSnapshot, _name, _snippet
from .storage import stable_id
from .taxonomy import _matches, TAXONOMY_VERSION

VERSION = 'semantic-evidence-2'
PROMPT_VERSION = 'semantic-extract-review-1'
# Explicit library type contracts, not a field-name dictionary.
CONTRACTS = {
    ('pydantic', 'EmailStr'): ('email_address', 'PII', 'email'),
    ('pydantic', 'NameEmail'): ('name_and_email', 'PII', 'email'),
    ('pydantic', 'SecretStr'): ('secret_string', 'AUTH', 'credential_bundle'),
    ('pydantic', 'SecretBytes'): ('secret_bytes', 'AUTH', 'credential_bundle'),
    ('pydantic.networks', 'EmailStr'): ('email_address', 'PII', 'email'),
}
GENERIC = {'data', 'value', 'payload', 'body', 'obj', 'item', 'result', 'x', 'v'}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def loc(path, node):
    return {'path': path, 'line': node.lineno, 'end_line': node.end_lineno,
            'column': node.col_offset, 'end_column': node.end_col_offset,
            'node_kind': type(node).__name__}


def node_at(snapshot, anchor):
    return next((n for n in ast.walk(snapshot.trees.get(anchor['path'], ast.Module(body=[], type_ignores=[])))
                 if all(getattr(n, k, None) == anchor[v] for k, v in
                        [('lineno','line'), ('end_lineno','end_line'), ('col_offset','column'), ('end_col_offset','end_column')])
                 and type(n).__name__ == anchor['node_kind']), None)


def safe_code(text):
    """Remove ALL literal values and comments, including unrecognized credentials.

    The exported view is a normalized AST, never claimed to be a verbatim quote.
    Exact source coordinates + digest allow local reinspection of the Git object.
    """
    class Hide(ast.NodeTransformer):
        def visit_Constant(self, node):
            return ast.copy_location(ast.Constant(value='<literal:'+type(node.value).__name__+'>'), node)
    try:
        return ast.unparse(Hide().visit(ast.parse(text)))
    except (SyntaxError, ValueError, RecursionError):
        return '<source withheld: non-Python or incomplete syntax>'


def leaf(meaning, category=None, subtype=None, *, nonsensitive=False):
    return {'meaning': meaning, 'category': category, 'subtype': subtype,
            'supported_non_sensitive': nonsensitive}


def type_contract(snapshot, path, annotation):
    name = _name(annotation)
    head, _, tail = name.partition('.')
    imported = verified_import(snapshot,path,annotation,head)
    if imported:
        # A spelling matching a library type is insufficient after rebinding.
        if any(p==path and target==head for p,_,target in snapshot.assignments) or (path,head) in snapshot.classes or (path,head) in snapshot.functions:
            return None
        module, symbol = imported
        contract = CONTRACTS.get((module, '.'.join(filter(None, (symbol, tail)))))
        if contract:
            return leaf(*contract)
    return None


def verified_import(snapshot,path,node,head):
    """Resolve visible imports; the detector's module index also contains locals."""
    scope=snapshot.symbol(path,node);function=snapshot.functions.get((path,scope))
    if function and head in [a.arg for a in (*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs)]:return None
    found=[]
    for candidate in ast.walk(snapshot.trees.get(path,ast.Module(body=[],type_ignores=[]))):
        if not isinstance(candidate,(ast.Import,ast.ImportFrom)) or snapshot.symbol(path,candidate) not in {'<module>',scope} or snapshot.conditional(path,candidate):continue
        if snapshot.position(candidate)>=snapshot.position(node):continue
        for item in candidate.names:
            alias=item.asname or (item.name.split('.')[0] if isinstance(candidate,ast.Import) else item.name)
            if alias==head:
                imported=(candidate.module or '',item.name) if isinstance(candidate,ast.ImportFrom) else (item.name,'')
                if isinstance(candidate,ast.ImportFrom):imported=('.'*candidate.level+imported[0],imported[1])
                found.append((snapshot.position(candidate),imported))
    return max(found)[1] if found else None


def exact_assignment(snapshot, path, node):
    """Do not let a local parameter/shadowing declaration fall through to globals."""
    scope = snapshot.symbol(path, node)
    local = snapshot.assignments.get((path, scope, node.id), [])
    enclosing=set();parent=snapshot.parents[path].get(node)
    while parent is not None:
        enclosing.add(parent);parent=snapshot.parents[path].get(parent)
    earlier = [n for n in local if snapshot.position(n) < snapshot.position(node) and n not in enclosing]
    if earlier:
        return max(earlier, key=snapshot.position)
    function = snapshot.functions.get((path, scope))
    params = [] if function is None else [a.arg for a in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)]
    if local or node.id in params or scope != '<module>':
        return None  # closure/global resolution is deliberately left pending
    return None


class Extractor:
    def __init__(self, files, repository, revision, *, max_chars=16000, one_hop=True, vocabulary=(), max_hops=1):
        self.snapshot = PythonSnapshot(files)
        self.repository, self.revision = repository, revision
        self.max_chars, self.one_hop, self.vocabulary = max_chars, one_hop, vocabulary
        self.max_hops = max_hops
        self.used = 0
        self.proofs = []
        self.gaps = []

    def proof(self, path, node, operation, children=(), **details):
        source = _snippet(self.snapshot.files[path], node)
        if self.used + len(source) > self.max_chars:
            self.gaps.append('context_budget_exceeded')
            return {'op': 'unknown', 'reason': 'context_budget_exceeded'}
        self.used += len(source)
        result = {'op': operation, 'anchor': loc(path, node), 'sha': self.revision,
                  'source_sha256': digest(self.snapshot.files[path]), 'snippet_sha256': digest(source),
                  'scope': self.snapshot.symbol(path, node), 'children': list(children), **details}
        self.proofs.append(result)
        return result

    def unknown(self, path, node, reason):
        self.gaps.append(reason)
        return self.proof(path, node, 'unknown', reason=reason)

    def annotation(self, path, annotation):
        contract = type_contract(self.snapshot, path, annotation)
        if contract:
            return self.proof(path, annotation, 'contract', proposed=contract)
        from .semantic_bindings import annotation_binding
        binding=annotation_binding(self.snapshot,path,annotation)
        if binding:return self.proof(path,annotation,'schema_document_binding',binding=binding)
        # A local nominal alias is a known declared meaning even outside the catalog.
        if isinstance(annotation, ast.Name):
            aliases = self.snapshot.assignments.get((path, '<module>', annotation.id), [])
            if len(aliases) == 1:
                alias = aliases[0]
                call = alias.value
                imp = self.snapshot.imports[path].get(_name(call.func)) if isinstance(call, ast.Call) else None
                if imp == ('typing', 'NewType') and call.args and isinstance(call.args[0], ast.Constant):
                    return self.proof(path, annotation, 'nominal',
                                      [self.proof(path, alias, 'definition')], proposed=leaf('declared_type:'+annotation.id))
        return self.unknown(path, annotation, 'annotation_without_semantic_contract')

    def resolve(self, path, node, bindings=None, calls=0, depth=0):
        bindings = bindings or {}
        if depth > 12:
            return self.unknown(path, node, 'local_depth_exceeded')
        def child(n, p=path, b=bindings, c=calls):
            return self.resolve(p, n, b, c, depth+1)
        from .semantic_bindings import python_binding
        binding = python_binding(self.snapshot,path,node)
        if binding:
            return self.proof(path,node,'schema_document_binding',binding=binding)
        if isinstance(node, ast.Constant):
            return self.proof(path, node, 'literal')
        if isinstance(node, ast.Name):
            from .semantic_flow import conditional_between, branch_assignments, visible_mutations
            assignment = exact_assignment(self.snapshot, path, node)
            if assignment and assignment.value is not None:
                if conditional_between(self.snapshot,path,assignment,node):
                    branch=branch_assignments(self.snapshot,path,node)
                    if branch:
                        conditional,arms=branch
                        return self.proof(path,node,'branch_merge',[child(a.value) for a in arms],
                                          condition=loc(path,conditional.test),definitions=[loc(path,a) for a in arms])
                    return self.unknown(path, node, 'conditional_assignment_unresolved')
                mutations = visible_mutations(self.snapshot,path,node,assignment)
                value = child(assignment.value)
                for event, keys, kind in sorted(mutations, key=lambda item: self.snapshot.position(item[0])):
                    if kind == 'set' and len(keys) == 1 and keys[0] is not None and not conditional_between(self.snapshot,path,event,node):
                        value = self.proof(path, event, 'write', [value, child(event.value)], field=keys[0],use_anchor=loc(path,node))
                    else:
                        return self.unknown(path, node, 'mutation_or_escape_unresolved')
                return self.proof(path, node, 'alias', [value], definition=loc(path, assignment))
            # Tuple destructuring is scoped and position checked (not indexed by the old detector).
            scope = self.snapshot.symbol(path, node)
            unpack = []
            for candidate in ast.walk(self.snapshot.trees[path]):
                if isinstance(candidate, ast.Assign) and self.snapshot.symbol(path, candidate) == scope and self.snapshot.position(candidate) < self.snapshot.position(node):
                    for target in candidate.targets:
                        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(candidate.value, (ast.Tuple, ast.List)) and len(target.elts) == len(candidate.value.elts):
                            unpack += [(candidate, i) for i, item in enumerate(target.elts) if isinstance(item, ast.Name) and item.id == node.id]
            if unpack:
                assignment, index = max(unpack, key=lambda pair:self.snapshot.position(pair[0]))
                if conditional_between(self.snapshot,path,assignment,node):
                    return self.unknown(path, node, 'conditional_unpack_unresolved')
                return self.proof(path, node, 'unpack', [child(assignment.value.elts[index])], definition=loc(path, assignment), index=index)
            if node.id in bindings:
                return self.proof(path, node, 'bound_parameter', [bindings[node.id]])
            function = self.snapshot.functions.get((path, scope))
            if function:
                for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
                    if arg.arg == node.id and arg.annotation:
                        model = self.snapshot.model(path, _name(arg.annotation))
                        if model:
                            mp, cls = model
                            fields = [(n.target.id, n.annotation) for n in cls.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)]
                            return self.proof(path, node, 'model_parameter', [self.annotation(mp, ann) for _, ann in fields],
                                              fields=[k for k, _ in fields], definition=loc(path, arg), model=loc(mp, cls))
                        return self.proof(path, node, 'parameter', [self.annotation(path, arg.annotation)], definition=loc(path, arg))
            # Exact scoped vocabulary must point to a source definition at this SHA.
            matches = [v for v in self.vocabulary if v['repository'] == self.repository and v['revision'] == self.revision
                       and v['module'] == path and v['scope'] == scope and v['field'] == node.id]
            if matches:
                return self.proof(path, node, 'vocabulary', entries=matches)
            return self.unknown(path, node, 'unresolved_binding')
        if isinstance(node, ast.Dict):
            fields, children = [], []
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    fields.append(key.value); children.append(child(value))
                elif key is None:
                    fields.append(None); children.append(child(value))
                else:
                    return self.unknown(path, node, 'dynamic_dictionary_key')
            return self.proof(path, node, 'object', children, fields=fields)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            key = node.attr if isinstance(node, ast.Attribute) else node.slice.value if isinstance(node.slice, ast.Constant) else None
            if key is None and isinstance(node,ast.Subscript) and isinstance(node.slice,ast.Name):
                assignment=exact_assignment(self.snapshot,path,node.slice)
                if assignment and isinstance(assignment.value,ast.Constant) and not self.snapshot.conditional(path,assignment):
                    key=assignment.value.value
            if key is None:
                return self.unknown(path, node, 'dynamic_projection')
            return self.proof(path, node, 'projection', [child(node.value)], field=str(key))
        if isinstance(node, ast.Call):
            name = _name(node.func)
            if name == 'dict' and not node.args:
                if any(p==path and target=='dict' for p,_,target in self.snapshot.assignments) or (path,'dict') in self.snapshot.functions or 'dict' in self.snapshot.imports[path]:
                    return self.unknown(path,node,'dictionary_constructor_shadowed')
                return self.proof(path, node, 'object', [child(k.value) for k in node.keywords], fields=[k.arg for k in node.keywords])
            if name in {'str', 'repr', 'json.dumps', 'dataclasses.asdict', 'asdict'} and len(node.args) == 1 and not node.keywords:
                # Keep association, but representation/redaction is NOT verified.
                return self.proof(path, node, 'serialization', [child(node.args[0])])
            model = self.snapshot.model(path,name)
            if model and constructor_unshadowed(self.snapshot,path,node):
                mp,cls=model
                if not cls.keywords and not any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in {'__new__','__init__'} for n in cls.body):
                    # Nominal identity is narrower than interpreting all fields.
                    # Unknown constructor arguments never become sensitive types.
                    return self.proof(path,node,'declared_constructor',model=loc(mp,cls),
                                      definition_sha256=digest(self.snapshot.files[mp]),declared_name=cls.name)
            target = self.snapshot.function(path, self.snapshot.symbol(path, node), name) if constructor_unshadowed(self.snapshot,path,node) else None
            if target and self.one_hop and calls < self.max_hops:
                tp, function = target
                allowed = (ast.Return, ast.Assign, ast.AnnAssign, ast.Expr)
                returns = [n for n in function.body if isinstance(n, ast.Return)]
                if len(returns) == 1 and returns[0].value and all(isinstance(n, allowed) for n in function.body):
                    # Reject side effects and implicit default/variadic binding guesses.
                    if any(isinstance(n, ast.Expr) and not isinstance(n.value, ast.Constant) for n in function.body):
                        return self.unknown(path, node, 'callee_side_effects_unresolved')
                    params = [a.arg for a in (*function.args.posonlyargs, *function.args.args)]
                    bound = {k:child(v) for k,v in zip(params, node.args)}
                    bound.update({k.arg:child(k.value) for k in node.keywords if k.arg})
                    if function.args.vararg or function.args.kwarg or any(k.arg is None for k in node.keywords) or len(node.args)>len(params):
                        return self.unknown(path, node, 'call_binding_unresolved')
                    result = child(returns[0].value, tp, bound, calls+1)
                    return self.proof(path, node, 'one_hop', [result], definition=loc(tp, function), return_anchor=loc(tp, returns[0]), bindings=bound)
            return self.unknown(path, node, 'one_hop_disabled_or_dynamic_call:'+name)
        if isinstance(node, ast.IfExp):
            return self.proof(path, node, 'alternatives', [child(node.body), child(node.orelse)])
        if isinstance(node, ast.Await):
            return self.proof(path, node, 'await_value', [child(node.value)])
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue, ast.List, ast.Tuple)):
            return self.proof(path, node, 'composite', [child(n) for n in ast.iter_child_nodes(node) if isinstance(n, ast.expr)])
        return self.unknown(path, node, 'unsupported_expression:'+type(node).__name__)


def interpret(proof):
    """Stage A proposals; Stage B does not use these to decide support."""
    op = proof['op']; children = [interpret(p) for p in proof.get('children', [])]
    if op == 'schema_document_binding':return proof['binding']['meanings']
    if op == 'declared_constructor':return [{**leaf('declared_type:'+proof['declared_name']),
                                             'interpretation_level':'nominal_constructor_not_field_contents'}]
    if op in {'contract', 'nominal'}:
        return [proof['proposed']]
    if op == 'vocabulary':
        return [leaf(v['meaning'], v.get('category'), v.get('subtype')) for v in proof['entries']]
    if op == 'literal':
        return [leaf('literal_value')]
    if op == 'projection':
        return _project(proof['children'][0], proof['field'], interpret)
    return [v for group in children for v in group]


def constructor_unshadowed(snapshot,path,node):
    head=_name(node.func).split('.')[0];scope=snapshot.symbol(path,node)
    function=snapshot.functions.get((path,scope))
    if function and head in [a.arg for a in (*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs)]:return False
    if any(p==path and target==head and (sc=='<module>' or sc==scope) for p,sc,target in snapshot.assignments):return False
    if head in snapshot.imports[path] and verified_import(snapshot,path,node,head)!=snapshot.imports[path][head]:return False
    return True


def _project(proof, field, evaluate):
    if proof['op'] in {'alias', 'bound_parameter', 'one_hop', 'serialization'}:
        return _project(proof['children'][0], field, evaluate)
    if proof['op'] == 'write':
        return evaluate(proof['children'][1]) if proof['field'] == field else _project(proof['children'][0], field, evaluate)
    if proof['op'] in {'object', 'model_parameter'}:
        matches = [i for i, name in enumerate(proof['fields']) if name == field]
        if matches:
            return evaluate(proof['children'][matches[-1]])
        for i, name in reversed(list(enumerate(proof['fields']))):
            if name is None:
                result = _project(proof['children'][i], field, evaluate)
                if result:
                    return result
    return []


def review(raw_files, repository, revision, proof):
    """Stage B: reparse raw historic files, validate coordinates/flow, derive verdict.

    No Stage A explanation/labels are accepted as evidence. This is a rule
    verifier, NOT a second model or a human reviewer. Unsupported constructs fail
    open into review queues, never into a non-sensitive label.
    """
    snapshot = PythonSnapshot(raw_files)
    reasons, checked = [], []
    def fail(reason):
        reasons.append(reason)
        return []
    def evaluate(p, bound=None, parents=()):
        op = p['op']; bound = bound or {}
        if 'anchor' not in p:
            return fail(p.get('reason', 'missing_anchor'))
        a = p['anchor']; path = a['path']; n = node_at(snapshot, a)
        if n is None or p.get('sha') != revision or p.get('source_sha256') != digest(raw_files.get(path, '')):
            return fail('history_or_source_mismatch')
        if digest(_snippet(raw_files[path], n)) != p['snippet_sha256'] or snapshot.symbol(path, n) != p['scope']:
            return fail('scope_or_span_mismatch')
        checked.append(a)
        children = p.get('children', [])
        def at(index, expected, expected_path=path):
            return index < len(children) and children[index].get('anchor') == loc(expected_path, expected)
        def ev(index):
            return evaluate(children[index], bound, parents)
        if op == 'schema_document_binding':
            from .semantic_bindings import python_binding, annotation_binding
            actual=annotation_binding(snapshot,path,n) if p.get('binding',{}).get('kind')=='declared_field_schema_metadata' else python_binding(snapshot,path,n)
            if actual!=p.get('binding'):return fail('schema_document_binding_mismatch')
            reasons.extend(actual['gaps'])
            return actual['meanings']
        if op == 'unknown':
            return fail(p.get('reason', 'semantic_unknown'))
        if op == 'branch_merge' and isinstance(n,ast.Name):
            from .semantic_flow import branch_assignments
            branch=branch_assignments(snapshot,path,n)
            if not branch or p['condition']!=loc(path,branch[0].test) or p['definitions']!=[loc(path,a) for a in branch[1]] or len(children)!=2 or any(not at(i,a.value) for i,a in enumerate(branch[1])):
                return fail('branch_binding_mismatch')
            reasons.append('conditional_path_feasibility_unverified')
            return [v for i in range(2) for v in ev(i)]
        if op == 'literal' and isinstance(n, ast.Constant):
            if n.value is None or isinstance(n.value, bool):
                return [leaf('fixed_null_or_boolean_literal', nonsensitive=True)]
            reasons.append('literal_shape_is_not_business_meaning')
            return [leaf('fixed_'+type(n.value).__name__+'_literal')]
        if op == 'contract':
            result = type_contract(snapshot, path, n)
            if result != p.get('proposed'):
                return fail('candidate_claim_contract_mismatch')
            return [result] if result else fail('type_contract_not_found')
        if op == 'definition':
            return []
        if op == 'declared_constructor' and isinstance(n,ast.Call):
            model=snapshot.model(path,_name(n.func))
            if not model or not constructor_unshadowed(snapshot,path,n):return fail('constructor_binding_mismatch')
            mp,cls=model
            if loc(mp,cls)!=p['model'] or digest(raw_files[mp])!=p['definition_sha256'] or cls.name!=p['declared_name'] or cls.keywords or any(isinstance(q,(ast.FunctionDef,ast.AsyncFunctionDef)) and q.name in {'__new__','__init__'} for q in cls.body):
                return fail('constructor_definition_mismatch')
            checked.append(loc(mp,cls))
            return [{**leaf('declared_type:'+cls.name),'interpretation_level':'nominal_constructor_not_field_contents'}]
        if op == 'nominal' and isinstance(n, ast.Name) and children:
            definition = node_at(snapshot, children[0]['anchor'])
            if not isinstance(definition, ast.Assign) or not isinstance(definition.value, ast.Call):
                return fail('nominal_definition_missing')
            imported = snapshot.imports[path].get(_name(definition.value.func))
            if imported != ('typing', 'NewType') or not any(isinstance(t, ast.Name) and t.id == n.id for t in definition.targets):
                return fail('nominal_definition_mismatch')
            evaluate(children[0], bound, parents)
            result=leaf('declared_type:'+n.id)
            return [result] if result==p.get('proposed') else fail('candidate_claim_nominal_mismatch')
        if op in {'alias', 'unpack'} and isinstance(n, ast.Name):
            definition = node_at(snapshot, p['definition'])
            from .semantic_flow import conditional_between, visible_mutations
            if definition is None or snapshot.symbol(path, definition) != snapshot.symbol(path, n) or snapshot.position(definition) >= snapshot.position(n) or conditional_between(snapshot,path,definition,n):
                return fail('assignment_scope_order_or_control_flow')
            if op == 'alias':
                actual = exact_assignment(snapshot, path, n)
                if actual is not definition:
                    return fail('shadowed_assignment')
                root = children[0]
                writes=[]
                while root.get('op') == 'write':
                    writes.append(root['anchor'])
                    root = root['children'][0]
                mutations=visible_mutations(snapshot,path,n,definition)
                if any(kind!='set' or len(keys)!=1 or keys[0] is None or conditional_between(snapshot,path,event,n) for event,keys,kind in mutations) or list(reversed(writes))!=[loc(path,event) for event,_,_ in mutations]:
                    return fail('mutation_chain_mismatch')
                if root.get('anchor') != loc(path, definition.value):
                    return fail('assignment_value_link_broken')
            else:
                i = p['index']
                if not isinstance(definition, ast.Assign) or not isinstance(definition.value, (ast.Tuple,ast.List)) or not any(isinstance(t,(ast.Tuple,ast.List)) and len(t.elts)>i and isinstance(t.elts[i],ast.Name) and t.elts[i].id==n.id for t in definition.targets) or not at(0, definition.value.elts[i]):
                    return fail('unpack_link_broken')
            return ev(0)
        if op == 'bound_parameter' and isinstance(n, ast.Name):
            if n.id not in bound or children[0] != bound[n.id]:
                return fail('call_argument_binding_broken')
            return evaluate(children[0], parents[-1] if parents else {}, parents[:-1])
        if op in {'parameter','model_parameter'} and isinstance(n, ast.Name):
            definition = node_at(snapshot, p['definition'])
            function = snapshot.functions.get((path,snapshot.symbol(path,n)))
            if not isinstance(definition, ast.arg) or definition.arg != n.id or function is None or definition not in [*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs]:
                return fail('parameter_scope_mismatch')
            if op == 'parameter':
                return ev(0) if at(0,definition.annotation) else fail('annotation_link_broken')
            model = snapshot.model(path,_name(definition.annotation))
            if not model or loc(model[0],model[1]) != p['model']:
                return fail('model_scope_mismatch')
            declared = [(f.target.id,f.annotation) for f in model[1].body if isinstance(f,ast.AnnAssign) and isinstance(f.target,ast.Name)]
            if p['fields'] != [k for k,_ in declared] or any(not at(i,ann,model[0]) for i,(_,ann) in enumerate(declared)):
                return fail('model_field_link_broken')
            return [v for c in children for v in evaluate(c,bound,parents)]
        if op == 'object':
            if isinstance(n, ast.Dict):
                fields = [k.value if isinstance(k,ast.Constant) else None for k in n.keys]; values=n.values
            elif isinstance(n,ast.Call) and _name(n.func)=='dict' and not n.args:
                fields=[k.arg for k in n.keywords]; values=[k.value for k in n.keywords]
            else:
                return fail('object_shape_mismatch')
            if fields != p['fields'] or len(children)!=len(values) or any(not at(i,v) for i,v in enumerate(values)):
                return fail('object_value_link_broken')
            return [v for c in children for v in evaluate(c,bound,parents)]
        if op == 'write' and isinstance(n,(ast.Assign,ast.AnnAssign)):
            from .semantic_flow import conditional_between
            target = n.targets[0] if isinstance(n,ast.Assign) else n.target
            key = target.attr if isinstance(target,ast.Attribute) else target.slice.value if isinstance(target,ast.Subscript) and isinstance(target.slice,ast.Constant) else None
            use=node_at(snapshot,p.get('use_anchor',{})) if p.get('use_anchor') else None
            if str(key)!=p['field'] or not at(1,n.value) or (conditional_between(snapshot,path,n,use) if use else snapshot.conditional(path,n)):
                return fail('field_write_mismatch')
            return ev(0)+ev(1)
        if op == 'projection' and isinstance(n,(ast.Attribute,ast.Subscript)):
            key=n.attr if isinstance(n,ast.Attribute) else n.slice.value if isinstance(n.slice,ast.Constant) else None
            if key is None and isinstance(n,ast.Subscript) and isinstance(n.slice,ast.Name):
                assignment=exact_assignment(snapshot,path,n.slice)
                if assignment and isinstance(assignment.value,ast.Constant) and not snapshot.conditional(path,assignment):key=assignment.value.value
            if str(key)!=p['field'] or not at(0,n.value):
                return fail('projection_link_broken')
            # Check the complete root first, then select only this field's values.
            root_reasons=len(reasons); ev(0)
            # Unrelated unknown object fields cannot invalidate an exact projection.
            if all(r.startswith(('annotation_without','unresolved_binding')) for r in reasons[root_reasons:]):
                del reasons[root_reasons:]
            result=_project(children[0],str(key),lambda q:evaluate(q,bound,parents))
            return result or fail('projected_field_unresolved')
        if op == 'one_hop' and isinstance(n,ast.Call):
            target=snapshot.function(path,snapshot.symbol(path,n),_name(n.func))
            if not target or not constructor_unshadowed(snapshot,path,n) or loc(*target)!=p['definition']:
                return fail('call_definition_mismatch')
            tp, fn=target; ret=node_at(snapshot,p['return_anchor'])
            if ret not in fn.body or not isinstance(ret,ast.Return) or not at(0,ret.value,tp):
                return fail('return_link_broken')
            params=[a.arg for a in (*fn.args.posonlyargs,*fn.args.args)]
            actual={k:loc(path,v) for k,v in zip(params,n.args)}
            actual.update({k.arg:loc(path,k.value) for k in n.keywords if k.arg})
            if {k:v.get('anchor') for k,v in p['bindings'].items()} != actual:
                return fail('call_argument_binding_broken')
            if any(isinstance(q,(ast.If,ast.For,ast.While,ast.Try,ast.With,ast.Match)) for q in fn.body):
                return fail('callee_control_flow_unresolved')
            return evaluate(children[0],p['bindings'],(*parents,bound))
        if op == 'await_value' and isinstance(n,ast.Await) and at(0,n.value):
            return ev(0)
        if op == 'serialization' and isinstance(n,ast.Call) and n.args and at(0,n.args[0]):
            reasons.append('serialization_or_sanitization_effect_unverified')
            return ev(0)
        if op in {'alternatives','composite'}:
            values=[n.body,n.orelse] if isinstance(n,ast.IfExp) else [q for q in ast.iter_child_nodes(n) if isinstance(q,ast.expr)]
            if len(values)!=len(children) or any(not at(i,v) for i,v in enumerate(values)):
                return fail('composite_link_broken')
            result=[v for c in children for v in evaluate(c,bound,parents)]
            if op=='alternatives' and len({v['meaning'] for v in result})>1:
                reasons.append('multiple_explanations_conflict')
            return result
        if op == 'vocabulary' and isinstance(n,ast.Name):
            result=[]
            for v in p['entries']:
                if (v['repository'],v['revision'],v['module'],v['scope'],v['field']) != (repository,revision,path,snapshot.symbol(path,n),n.id):
                    return fail('vocabulary_scope_or_version_mismatch')
                text=raw_files.get(v['definition_path'],'')
                # A definition remains a declared interpretation, not proof it is true.
                if digest(text)!=v['definition_sha256'] or v['definition_quote'] not in text:
                    return fail('vocabulary_definition_missing_or_stale')
                result.append(leaf(v['meaning'],v.get('category'),v.get('subtype')))
            reasons.append('scoped_vocabulary_binding_requires_review')
            return result
        return fail('unsupported_or_forged_proof_operation')
    values=evaluate(proof)
    values=list({stable_id(v):v for v in values}.values())
    mismatch=any(r.endswith(('_mismatch','_broken')) or r in {
        'shadowed_assignment','unsupported_or_forged_proof_operation',
        'vocabulary_definition_missing_or_stale','assignment_scope_order_or_control_flow'} for r in reasons)
    status='unsupported' if mismatch else 'ambiguous' if reasons or not values else 'supported'
    return {'status':status,'reasons':sorted(set(reasons)) or ['raw_ast_and_flow_witnesses_checked'],
            'checked_anchors':checked,'derived_meanings':values,'method':'independent_rule_evidence_replay',
            'model':None,'human_confirmed':False,'model_stage':'not_run','prompt_version':PROMPT_VERSION}


def analyze_use(files, repository, revision, path, node_anchor, *, max_chars=16000, one_hop=True, vocabulary=(), max_hops=1):
    if node_anchor.get('parser')=='tree_sitter':
        from .semantic_ast import analyze
        return analyze(files,repository,revision,path,node_anchor,max_chars=max_chars,one_hop=one_hop,max_hops=max_hops)
    extractor=Extractor(files,repository,revision,max_chars=max_chars,one_hop=one_hop,vocabulary=vocabulary,max_hops=max_hops)
    node=node_at(extractor.snapshot,node_anchor)
    if node is None:
        return {'review':{'status':'ambiguous','reasons':['use_site_or_history_missing'],'derived_meanings':[],
                          'method':'independent_rule_evidence_replay','model_stage':'not_run','human_confirmed':False},
                'proposal':[],'proof':None,'context_chars':0,'gaps':['use_site_or_history_missing']}
    proof=extractor.resolve(path,node)
    proposal=interpret(proof)
    # Reparse independent raw evidence; do not feed extractor explanations to reviewer.
    verdict=review(files,repository,revision,proof)
    return {'proposal':proposal,'proof':proof,'review':verdict,'context_chars':extractor.used,
            'gaps':sorted(set(extractor.gaps)), 'transformation':transformation(files,revision,proof,verdict),
            'name_only_hints': [{'category':r[0],'subtype':r[1],'basis':'name_only_not_supported'} for r in _matches(_name(node))]}


def transformation(files,revision,proof,verdict):
    """Check a narrow noninterference property without executing target code.

    A statically fixed helper return carries no caller input in this argument.
    This says nothing about side channels, other logs, or hashing/anonymization.
    """
    result={'status':'unverified','runtime_verified':False,'target_code_executed':False,
            'scope':'this_log_argument_only','input_independent':None}
    if verdict['status']=='unsupported':return result
    snapshot=PythonSnapshot(files)
    def check(p,through_call=False):
        a=p.get('anchor');n=node_at(snapshot,a) if a else None
        if n is None or p.get('sha')!=revision or p.get('source_sha256')!=digest(files.get(a['path'],'')):return False
        if p['op']=='literal':return through_call and isinstance(n,ast.Constant)
        if p['op'] in {'alias','await_value'}:return check(p['children'][0],through_call)
        if p['op']=='one_hop':
            return check(p['children'][0],True)
        if p['op']=='object':return through_call and all(check(c,through_call) for c in p['children'])
        if p['op']=='alternatives':
            nodes=[node_at(snapshot,c['anchor']) for c in p['children']]
            return len({ast.dump(v) for v in nodes if v is not None})==1 and all(check(c,through_call) for c in p['children'])
        return False
    if check(proof):
        result.update(status='verified_static_input_independent_output',input_independent=True,
                      method='raw_AST_constant_return_noninterference',evidence_anchor=proof.get('anchor'))
    return result


def classify(result):
    review_row=result['review']; values=review_row['derived_meanings']; reasons=review_row['reasons']
    types=[{'category':v['category'],'subtype':v['subtype']} for v in values if v.get('category')]
    supported=review_row['status']=='supported'
    if any('conflict' in r for r in reasons): queue='conflicting_explanations'
    elif any(any(k in r for k in ('missing','budget','history','depth')) for r in reasons): queue='context_or_history_missing'
    elif not supported: queue='semantic_unknown'
    elif values and all(v['supported_non_sensitive'] for v in values): queue='supported_non_sensitive'
    elif any(v['meaning'].startswith('declared_type:') or v['meaning'].startswith('fixed_') for v in values) and not types: queue='known_semantics_unmapped'
    elif not types: queue='known_semantics_unmapped'
    else: queue='mapped_supported'
    return {'queue':queue,'meanings':values,'types':types if supported else [],
            'possible_types_pending_review':types if not supported else [],'taxonomy_version':TAXONOMY_VERSION,
            'catalog_is_exhaustive':False,'human_review_status':'pending'}


def public_proof(proof, files):
    if proof is None:return None
    if proof.get('anchor',{}).get('parser')=='tree_sitter':
        from .semantic_ast import public_proof as ast_proof
        return ast_proof(proof,files)
    result=copy.deepcopy(proof)
    snapshot=PythonSnapshot(files)
    def clean(p):
        if 'anchor' in p:
            a=p['anchor']; source=files.get(a['path'],'')
            n=node_at(snapshot,a)
            p['code_view']=safe_code(_snippet(source,n)) if n else '<missing>'
            p['code_view_is_verbatim']=False
        for v in p.get('entries',[]):
            v['definition_quote_sha256']=digest(v.pop('definition_quote'))
        for c in p.get('children',[]):clean(c)
        for c in p.get('bindings',{}).values():clean(c)
    clean(result)
    return result
