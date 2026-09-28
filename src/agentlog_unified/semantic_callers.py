"""Bounded caller lookup in an exact-revision snapshot, without name-only edges."""
from __future__ import annotations

import ast
from pathlib import Path

from .detector import _name
from .semantic_ast import Syntax
from .semantic_evidence import constructor_unshadowed, exact_assignment, loc
from .semantic_flow import conditional_between, visible_mutations

TREE_SUFFIXES = {'.java', '.go', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}


def _class(node):
    parent = node.parent
    while parent:
        if parent.type in {'class_declaration', 'interface_declaration', 'enum_declaration', 'record_declaration'}:
            return parent
        if parent.type == 'class_body' and parent.parent.type == 'object_creation_expression':
            return parent  # Anonymous classes must not inherit their enclosing this.
        parent = parent.parent
    return None


def _names(syntax, params):
    result = []
    for param in params.named_children if params else []:
        if param.type in {'spread_parameter', 'rest_pattern', 'variadic_parameter_declaration'}:
            return []
        nodes = param.children_by_field_name('name') or [param.child_by_field_name('pattern') or param]
        names = [syntax.text(n) for n in nodes]
        if not all(n.isidentifier() for n in names):
            return []
        result.extend(names)
    return result


def _python_arguments(function, call, receiver=None):
    """Bind explicit positional/keyword/default arguments without executing code."""
    args = function.args; declared_positional = [*args.posonlyargs, *args.args]; positional=list(declared_positional)
    implicit = positional.pop(0) if receiver is not None and positional else None
    if receiver is not None and implicit is None:return None
    if args.vararg or args.kwarg or any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return None
    if len(call.args) > len(positional):
        return None
    bound = {p.arg: (v, 'positional') for p, v in zip(positional, call.args)}
    allowed = {p.arg for p in [*args.args, *args.kwonlyargs]}
    if implicit:allowed.discard(implicit.arg)
    for keyword in call.keywords:
        if keyword.arg not in allowed or keyword.arg in bound:
            return None
        bound[keyword.arg] = (keyword.value, 'keyword')
    defaults = {p.arg: d for p, d in zip(declared_positional[len(declared_positional)-len(args.defaults):], args.defaults)}
    defaults.update({p.arg: d for p, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None})
    for parameter in [*positional, *args.kwonlyargs]:
        if parameter.arg not in bound:
            if parameter.arg not in defaults:
                return None
            bound[parameter.arg] = (defaults[parameter.arg], 'default')
    if implicit:bound[implicit.arg]=(receiver,'receiver')
    return bound


def _method_receiver(snapshot,path,call,target_path,cls,method,depth=0):
    """Return the declared/construction witness; never equate a spelling to a type."""
    if depth>4:return None
    expr=call.func.value
    def resolve(expr,depth=0):
        if depth>4:return None
        if isinstance(expr,ast.Call):
            if not constructor_unshadowed(snapshot,path,expr):return None
            fn=snapshot.functions.get((path,snapshot.symbol(path,expr)))
            if fn and any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n is not cls and n.name==_name(expr.func).split('.')[0] for n in ast.walk(fn)):return None
            model=snapshot.model(path,_name(expr.func))
            if model==(target_path,cls):return {'kind':'explicit_constructor','anchor':loc(path,expr)}
        if isinstance(expr,(ast.Name,ast.Attribute)):
            model=snapshot.model(path,_name(expr))
            if model==(target_path,cls) and not any(pp==path and name==_name(expr).split('.')[0] for pp,_,name in snapshot.assignments):
                fn=snapshot.functions.get((path,snapshot.symbol(path,expr)))
                if not fn or _name(expr) not in [a.arg for a in (*fn.args.posonlyargs,*fn.args.args,*fn.args.kwonlyargs)]:
                    return {'kind':'explicit_class','anchor':loc(path,expr)}
        if not isinstance(expr,ast.Name):return None
        assignment=exact_assignment(snapshot,path,expr)
        if assignment:
            if conditional_between(snapshot,path,assignment,expr):return None
            mutations=visible_mutations(snapshot,path,expr,assignment)
            if any(kind!='set' or keys==[method.name] or not keys for _,keys,kind in mutations):return None
            witness=resolve(assignment.value,depth+1)
            if witness:return {**witness,'assignment_anchors':witness.get('assignment_anchors',[])+[loc(path,assignment)]}
            return None
        fn=snapshot.functions.get((path,snapshot.symbol(path,expr)))
        if fn:
            params=[*fn.args.posonlyargs,*fn.args.args,*fn.args.kwonlyargs]
            for param in params:
                if param.arg!=expr.id:continue
                if any(kind!='set' or keys==[method.name] or not keys for _,keys,kind in visible_mutations(snapshot,path,expr,param)):return None
                if param.annotation and snapshot.model(path,_name(param.annotation))==(target_path,cls):
                    return {'kind':'annotated_receiver_possible_subclass','anchor':loc(path,param)}
                owner=snapshot.parents[path].get(fn)
                if owner is cls and params[0] is param and not fn.decorator_list:
                    return {'kind':'implicit_receiver_possible_subclass','anchor':loc(path,param)}
        return None
    return resolve(expr)


def _python_method_callers(ctx,path,function,cls,parameter_name,max_files):
    snap=ctx.python;gaps=[];result=[]
    if not isinstance(snap.parents[path].get(cls),ast.Module) or cls.decorator_list or cls.keywords:
        return [],['python_dynamic_class_unresolved'],0
    # Generic[T] contributes typing metadata; general inheritance needs an MRO.
    if any(not (isinstance(b,ast.Name) and b.id=='object' or isinstance(b,ast.Subscript)
                and snap.imports[path].get(_name(b.value))==('typing','Generic')) for b in cls.bases):
        return [],['python_inheritance_mro_unresolved'],0
    methods=[n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
    if sum(n.name==function.name for n in methods)!=1 or any(n.name in {'__new__','__getattr__','__getattribute__'} for n in methods):
        return [],['python_dynamic_method_lookup_unresolved'],0
    decorators=[_name(d) for d in function.decorator_list]
    if decorators not in ([],['staticmethod'],['classmethod']):return [],['python_method_decorator_unresolved'],0
    if any(d in snap.imports[path] or (path,d) in snap.functions or any(pp==path and name==d for pp,_,name in snap.assignments) for d in decorators):
        return [],['python_method_decorator_shadowed'],0
    # A method can be replaced on the class or on self in __init__.
    for n in ast.walk(snap.trees[path]):
        targets=n.targets if isinstance(n,ast.Assign) else [n.target] if isinstance(n,(ast.AnnAssign,ast.AugAssign)) else []
        if any(isinstance(t,ast.Attribute) and t.attr==function.name for t in targets):
            return [],['python_method_reassignment_unresolved'],0
        if isinstance(n,ast.Call) and _name(n.func) in {'setattr','delattr'}:
            return [],['python_dynamic_attribute_write_unresolved'],0
    paths=sorted(snap.trees,key=lambda p:(p!=path,p))
    for p in paths[:max_files]:
        for call in ast.walk(snap.trees[p]):
            if not isinstance(call,ast.Call) or not isinstance(call.func,ast.Attribute) or call.func.attr!=function.name:continue
            witness=_method_receiver(snap,p,call,path,cls,function)
            if not witness:gaps.append('python_receiver_binding_unresolved');continue
            is_class=witness['kind']=='explicit_class'
            if is_class and not decorators:
                # Explicit Class.method(obj, ...) uses normal unbound arguments.
                receiver=None
            else:receiver=None if decorators==['staticmethod'] else call.func.value
            if decorators==['classmethod'] and parameter_name==function.args.args[0].arg:
                gaps.append('python_classmethod_class_value_unresolved');continue
            bindings=_python_arguments(function,call,receiver)
            if bindings is None or parameter_name not in bindings:
                gaps.append('argument_binding_unpack_or_arity_unresolved');continue
            actual,kind=bindings[parameter_name]
            result.append({'call_anchor':loc(p,call),'actual_anchor':loc(path if kind=='default' else p,actual),
                'definition_anchor':loc(path,function),'class_anchor':loc(path,cls),
                'receiver_evidence':witness,'binding_kind':kind,'status':'possible',
                'resolution':'python_ast_bound_method','dispatch_completeness':'runtime_replacement_or_subclass_not_excluded'})
    if len(paths)>max_files:gaps.append('caller_file_budget_exceeded')
    if not result:gaps.append('no_resolved_caller_in_snapshot')
    return result,sorted(set(gaps)),min(len(paths),max_files)


def caller_arguments(ctx, formal, parameter_name, *, max_files=64):
    path = formal['path']; node = ctx.node(formal); suffix = Path(path).suffix
    result = []; gaps = []; files_seen = 0
    if suffix == '.py':
        snap = ctx.python; function = snap.parents[path].get(node)
        while function is not None and not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = snap.parents[path].get(function)
        owner=snap.parents[path].get(function)
        if isinstance(owner,ast.ClassDef):
            return _python_method_callers(ctx,path,function,owner,parameter_name,max_files)
        if function is None or not isinstance(snap.parents[path].get(function), ast.Module) or function.decorator_list:
            return [], ['python_method_nested_or_decorated_dispatch_unresolved'], 0
        if sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function.name for n in snap.trees[path].body) != 1:
            return [], ['duplicate_function_definition'], 0
        paths = sorted(snap.trees, key=lambda p: (p != path, p))
        for p in paths[:max_files]:
            files_seen += 1
            for call in ast.walk(snap.trees[p]):
                if not isinstance(call, ast.Call) or _name(call.func).split('.')[-1] != function.name:
                    # Imported aliases are checked too, using the existing import resolver.
                    if not isinstance(call, ast.Call) or _name(call.func).split('.')[0] not in snap.imports[p]:
                        continue
                if not constructor_unshadowed(snap, p, call):
                    gaps.append('shadowed_callable_not_bound'); continue
                head = _name(call.func).split('.')[0]
                # A nested def/class binds a local name too; the shared value
                # assignment index deliberately does not index these bindings.
                parent = snap.parents[p].get(call); scopes = []
                while parent is not None:
                    if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                           ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                        scopes.append(parent)
                    parent = snap.parents[p].get(parent)
                if len(scopes) > 1 or any(not isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef)) for x in scopes):
                    gaps.append('nested_caller_scope_unresolved'); continue
                owner = scopes[0] if scopes else snap.trees[p]
                if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                       and n.name == head and n is not function for n in ast.walk(owner)):
                    gaps.append('shadowed_callable_not_bound'); continue
                target = snap.function(p, snap.symbol(p, call), _name(call.func))
                if target != (path, function):
                    continue
                bindings = _python_arguments(function, call)
                if bindings is None or parameter_name not in bindings:
                    gaps.append('argument_binding_unpack_or_arity_unresolved'); continue
                actual, kind = bindings[parameter_name]; actual_path = path if kind == 'default' else p
                result.append({'call_anchor': loc(p, call), 'actual_anchor': loc(actual_path, actual),
                               'definition_anchor': loc(path, function), 'binding_kind': kind,
                               'status': 'structural_ast' if p == path else 'possible',
                               'resolution': 'same_module_function' if p == path else 'explicit_import_static_target'})
    elif suffix in TREE_SUFFIXES:
        s = ctx.syntax[path]; function = s.function(node)
        if function is None:
            return [], ['enclosing_function_missing'], 0
        names = _names(s, function.child_by_field_name('parameters'))
        if parameter_name not in names or len(names) != len(set(names)):
            return [], ['destructured_or_variadic_parameter_unresolved'], 0
        name = s.text(function.child_by_field_name('name')); owner = _class(function)
        java = suffix == '.java'
        if java:
            modifiers = next((s.text(c).split() for c in function.children if c.type == 'modifiers'), [])
            if not {'private', 'static'} & set(modifiers):
                return [], ['java_virtual_dispatch_unresolved'], 0
            methods = [f for f in s.nodes if f.type == 'method_declaration' and _class(f) == owner and s.text(f.child_by_field_name('name')) == name]
            if len(methods) != 1:
                return [], ['java_overload_unresolved'], 0
            paths = [path]
        else:
            if function.type != 'function_declaration' or s.function(function) is not None:
                return [], ['member_or_nested_function_dispatch_unresolved'], 0
            # ponytail: JS/TS same-module and Go same-directory package functions only.
            paths = ([p for p in ctx.files if Path(p).suffix == '.go' and Path(p).parent == Path(path).parent]
                     if suffix == '.go' else [path])
        syntaxes = []
        for p in sorted(paths, key=lambda p: (p != path, p))[:max_files]:
            if p not in ctx.syntax:
                ctx.syntax[p] = Syntax(p, ctx.files[p])
            syntaxes.append(ctx.syntax[p]); files_seen += 1
        if not java:
            definitions = [(ss.path, f) for ss in syntaxes for f in ss.nodes if f.type == 'function_declaration'
                           and ss.text(f.child_by_field_name('name')) == name]
            if definitions != [(path, function)]:
                return [], ['package_or_module_function_ambiguous'], files_seen
        for ss in syntaxes:
            if suffix == '.go':
                package = lambda syntax: [syntax.text(n) for n in syntax.root.named_children if n.type == 'package_clause']
                if package(ss) != package(s):
                    gaps.append('go_package_mismatch'); continue
            for call in ss.nodes:
                if call.type != ('method_invocation' if java else 'call_expression'):
                    continue
                callee = call.child_by_field_name('name' if java else 'function')
                if ss.text(callee) != name:
                    continue
                if call.has_error or (java and _class(call) != owner):
                    continue
                if java:
                    receiver = call.child_by_field_name('object')
                    allowed = {'', 'this'} | ({s.text(owner.child_by_field_name('name'))} if 'static' in modifiers and owner else set())
                    if ss.text(receiver) not in allowed:
                        gaps.append('java_receiver_unresolved'); continue
                else:
                    caller = ss.function(call)
                    if callee.type != 'identifier' or ss.declarations(callee) or (caller and name in _names(ss, caller.child_by_field_name('parameters'))):
                        gaps.append('shadowed_callable_not_bound'); continue
                    # Reject reassigned module bindings, including later assignments.
                    if any((n.type in {'assignment_expression','assignment_statement','short_var_declaration'}
                            and ss.text(n.child_by_field_name('left')) == name)
                           or (n.type == 'variable_declarator' and ss.text(n.child_by_field_name('name')) == name)
                           for n in ss.nodes):
                        gaps.append('reassigned_callable_not_bound'); continue
                args = call.child_by_field_name('arguments')
                values = args.named_children if args else []
                if len(values) != len(names) or any(v.type in {'spread_element', 'variadic_argument'} for v in values):
                    gaps.append('argument_binding_unpack_or_arity_unresolved'); continue
                result.append({'call_anchor': ss.anchor(call), 'actual_anchor': ss.anchor(values[names.index(parameter_name)]),
                               'definition_anchor': s.anchor(function), 'binding_kind': 'positional',
                               'status': 'structural_ast', 'resolution': 'private_or_static_same_class' if java else 'explicit_package_function'})
    else:
        return [], ['caller_language_unsupported'], 0
    if len(paths) > max_files:
        gaps.append('caller_file_budget_exceeded')
    if not result:
        gaps.append('no_resolved_caller_in_snapshot')
    return result, sorted(set(gaps)), files_seen
