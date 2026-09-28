"""Explicit historical schema/document bindings. Never search by field spelling.

Only local, bounded references are followed. A schema is a declared contract,
not evidence that a validator ran or that its annotations were enforced.
"""
from __future__ import annotations

import ast
import json
import posixpath
import re

from .detector import _name


def literal(snapshot, path, node, seen=(), references=None):
    """Resolve data literals and same-module constants without executing code."""
    if len(seen)>8:
        raise ValueError('schema_reference_depth_exceeded')
    if isinstance(node, ast.Name):
        scope=snapshot.symbol(path,node);key=(path,scope,node.id)
        fn=snapshot.functions.get((path,scope))
        if fn and node.id in [a.arg for a in (*fn.args.posonlyargs,*fn.args.args,*fn.args.kwonlyargs)]:
            raise ValueError('schema_parameter_not_static_data')
        local=snapshot.assignments.get((path,scope,node.id),[])
        definitions=local or snapshot.assignments.get((path,'<module>',node.id),[])
        definitions=[n for n in definitions if snapshot.position(n)<snapshot.position(node)]
        ancestors=set();parent=snapshot.parents[path].get(node)
        while parent is not None:ancestors.add(parent);parent=snapshot.parents[path].get(parent)
        if any(event not in ancestors and snapshot.position(event)<snapshot.position(node)
               for (p,sc,name),events in snapshot.mutations.items() if p==path and sc in {'<module>',scope} and name==node.id
               for event,_,_ in events):raise ValueError('schema_mutation_or_escape_unresolved')
        if not definitions and not local and key not in seen:
            from .semantic_evidence import verified_import, digest, loc
            imported=verified_import(snapshot,path,node,node.id)
            target=snapshot.imported(path,node.id) if imported else None
            if target:
                tp,name=target
                candidates=snapshot.assignments.get((tp,'<module>',name),[])
                if len(candidates)!=1 or snapshot.conditional(tp,candidates[0]):raise ValueError('imported_schema_binding_unresolved')
                if any(p==tp and variable==name and events for (p,sc,variable),events in snapshot.mutations.items()):raise ValueError('imported_schema_mutation_unresolved')
                if references is not None:references.append({'path':tp,'source_sha256':digest(snapshot.files[tp]),'anchor':loc(tp,candidates[0]),'binding':'verified_imported_static_schema'})
                return literal(snapshot,tp,candidates[0].value,(*seen,key),references)
        if key in seen or len(definitions)!=1:
            raise ValueError('schema_constant_binding_unresolved')
        if snapshot.conditional(path,definitions[0]):raise ValueError('schema_conditional_binding_unresolved')
        return literal(snapshot,path,definitions[0].value,(*seen,key),references)
    if isinstance(node,ast.Call) and _name(node.func) in {'json.load','json.loads'} and len(node.args)==1:
        if snapshot.imports[path].get('json')!=('json','') or any(p==path and name=='json' for p,_,name in snapshot.assignments):
            raise ValueError('schema_loader_import_shadowed')
        arg=node.args[0]
        # Explicit literal open path, read from this historical snapshot only.
        if _name(node.func)=='json.load' and isinstance(arg,ast.Call) and _name(arg.func)=='open' and arg.args and isinstance(arg.args[0],ast.Constant) and isinstance(arg.args[0].value,str):
            if 'open' in snapshot.imports[path] or (path,'open') in snapshot.functions or any(p==path and name=='open' for p,_,name in snapshot.assignments):
                raise ValueError('schema_loader_open_shadowed')
            relative=arg.args[0].value
            candidates={relative,posixpath.normpath(posixpath.join(posixpath.dirname(path),relative))}
            available=[p for p in candidates if not p.startswith(('/','../')) and p in snapshot.files]
            if len(available)!=1:raise ValueError('schema_file_path_missing_or_ambiguous')
            return json.loads(snapshot.files[available[0]])
        if _name(node.func)=='json.loads':return json.loads(literal(snapshot,path,arg,seen,references))
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        raise ValueError('schema_not_static_data') from None


def reference_files(files, path, audit=None):
    """Include only explicitly referenced local schema/docs, at the caller SHA."""
    found={};queue=[path];seen=set();audit=audit if audit is not None else []
    while queue and len(seen)<16:
        current=queue.pop(0)
        if current in seen:continue
        seen.add(current)
        # Selection is only context acquisition, never a semantic assertion.
        for relative in re.findall(r'''["'(]([^\s"'()]+\.(?:json|ya?ml|md))(?:#[^\s"'()]*)?["')]''',files.get(current,'')):
            target=posixpath.normpath(posixpath.join(posixpath.dirname(current),relative))
            if target.startswith('../') or target.startswith('/') or '://' in relative:
                audit.append({'reason':'external_context_reference_unresolved','reference_from':current});continue
            if target in files:
                found[target]=files[target];queue.append(target)
            else:audit.append({'reason':'referenced_context_file_missing','path':target,'reference_from':current})
    if queue:audit.append({'reason':'context_reference_budget_exceeded','remaining_references':len(queue)})
    return found


def schema_leaf(schema):
    from .semantic_evidence import leaf, digest
    fmt=schema.get('format')
    if fmt=='email':return leaf('declared_schema_format:email','PII','email')
    if fmt in {'ipv4','ipv6'}:return leaf('declared_schema_format:'+fmt,'QID','network_identifier')
    # Primitive JSON types alone do not establish a business meaning.
    if isinstance(schema.get('description'),str) and schema['description'].strip():
        return {**leaf('documented_schema_value'), 'definition_sha256':digest(schema['description'])}
    if isinstance(schema.get('title'),str) and schema['title'].strip():
        return {**leaf('declared_schema_title'), 'definition_sha256':digest(schema['title'])}
    return None


def annotation_binding(snapshot,path,annotation):
    """Pydantic Field / dataclasses.field metadata bound to this exact field."""
    from .semantic_evidence import loc,verified_import
    parent=snapshot.parents[path].get(annotation)
    if not isinstance(parent,ast.AnnAssign) or parent.annotation is not annotation or not isinstance(parent.value,ast.Call):return None
    call=parent.value;head,_,tail=_name(call.func).partition('.')
    imported=verified_import(snapshot,path,annotation,head)
    qualified=(imported[0],'.'.join(filter(None,(imported[1],tail)))) if imported else None
    if qualified not in {('pydantic','Field'),('dataclasses','field')}:return None
    if any(p==path and name==head for p,_,name in snapshot.assignments) or (path,head) in snapshot.functions:return None
    schema={}
    for keyword in call.keywords:
        if keyword.arg not in {'description','title','json_schema_extra','metadata'}:continue
        try:value=literal(snapshot,path,keyword.value)
        except ValueError:continue
        if keyword.arg in {'json_schema_extra','metadata'} and isinstance(value,dict):schema.update(value)
        elif keyword.arg in {'description','title'} and isinstance(value,str):schema[keyword.arg]=value
    if not schema:return None
    return {'kind':'declared_field_schema_metadata','binding_anchor':loc(path,parent),
            **schema_meanings(schema,snapshot.files,path)}


def schema_meanings(schema, files, document_path, projection=(), *, max_nodes=128):
    """Resolve JSON Pointer $refs without network or external filesystem access."""
    from .semantic_evidence import digest
    visited=[];gaps=[];count=0
    def visit(value,path,root,keys,chain=()):
        nonlocal count
        count+=1
        if count>max_nodes or len(chain)>16:
            gaps.append('schema_context_budget_exceeded');return []
        if not isinstance(value,dict):
            gaps.append('schema_shape_unresolved');return []
        if '$id' in value:
            gaps.append('schema_id_base_resolution_unimplemented');return []
        if '$ref' in value:
            ref=value['$ref']
            if not isinstance(ref,str) or '://' in ref or ref.startswith('/'):
                gaps.append('remote_or_absolute_schema_reference_unresolved');return []
            relative,_,fragment=ref.partition('#')
            target=posixpath.normpath(posixpath.join(posixpath.dirname(path),relative)) if relative else path
            key=(target,fragment,tuple(keys))
            if key in chain:
                gaps.append('schema_reference_cycle');return []
            if target.startswith('../'):
                gaps.append('schema_reference_outside_repository');return []
            doc=root
            if relative:
                # An inline Python schema has no established retrieval URI.
                # A matching repository file supplies context, not a proven base.
                if path.endswith('.py'):gaps.append('schema_reference_base_unverified')
                if target not in files:
                    gaps.append('schema_reference_file_missing');return []
                try:
                    import yaml
                    doc=json.loads(files[target]) if target.endswith('.json') else yaml.safe_load(files[target])
                except (ValueError,yaml.YAMLError):
                    gaps.append('schema_reference_parse_failed');return []
                visited.append({'path':target,'source_sha256':digest(files[target]),'pointer':fragment})
            pointed=doc
            try:
                if fragment and not fragment.startswith('/'):
                    raise KeyError(fragment)
                for segment in fragment.split('/')[1:]:
                    pointed=pointed[segment.replace('~1','/').replace('~0','~')]
            except (KeyError,TypeError,IndexError):
                gaps.append('schema_pointer_missing');return []
            # Sibling constraints can change the meaning; do not silently ignore.
            if set(value)-{'$ref','$comment'}:
                gaps.append('schema_reference_siblings_require_review')
            return visit(pointed,target,doc,keys,(*chain,key))
        if any(k in value for k in ('allOf','anyOf','oneOf','if','not')):
            gaps.append('schema_composition_requires_review');return []
        if keys:
            prop=value.get('properties',{}).get(str(keys[0]))
            if prop is None:
                gaps.append('schema_projected_property_missing');return []
            return visit(prop,path,root,keys[1:],chain)
        if isinstance(value.get('properties'),dict):
            return [m for child in value['properties'].values() for m in visit(child,path,root,(),chain)]
        meaning=schema_leaf(value)
        if not meaning:gaps.append('schema_without_semantic_contract')
        return [meaning] if meaning else []
    meanings=visit(schema,document_path,schema,tuple(projection))
    return {'meanings':meanings,'gaps':sorted(set(gaps)),'references':visited,
            'contract_status':'declared_only_not_runtime_validated'}


def python_binding(snapshot, path, node):
    """Bind a parameter/use to a dominating jsonschema.validate or docstring.

    No arbitrary call-name matching: validate must be the imported library symbol.
    Mutated/conditional values are rejected rather than borrowing an old schema.
    """
    from .semantic_evidence import digest, exact_assignment, loc, leaf,verified_import
    scope=snapshot.symbol(path,node);function=snapshot.functions.get((path,scope))
    base=node;projection=[]
    while isinstance(base,(ast.Attribute,ast.Subscript)):
        key=base.attr if isinstance(base,ast.Attribute) else base.slice.value if isinstance(base.slice,ast.Constant) else None
        if key is None:return None
        projection.insert(0,key);base=base.value
    if not isinstance(base,ast.Name):return None
    bindings=[]
    for call in ast.walk(function or snapshot.trees[path]):
        if not isinstance(call,ast.Call) or snapshot.symbol(path,call)!=scope or snapshot.position(call)>=snapshot.position(node):continue
        if snapshot.conditional(path,call):continue
        name=_name(call.func);head,_,tail=name.partition('.')
        imported=verified_import(snapshot,path,call,head)
        if imported not in {('jsonschema','validate'),('jsonschema','')} or (tail and tail!='validate'):continue
        if imported==('jsonschema','') and tail!='validate':continue
        if any(p==path and target==head for p,_,target in snapshot.assignments) or (path,head) in snapshot.functions:continue
        args={k.arg:k.value for k in call.keywords if k.arg}
        instance=call.args[0] if call.args else args.get('instance')
        schema_node=call.args[1] if len(call.args)>1 else args.get('schema')
        if not isinstance(instance,ast.Name) or instance.id!=base.id or schema_node is None:continue
        definition=exact_assignment(snapshot,path,base)
        if definition and snapshot.position(definition)>snapshot.position(call):continue
        if any(snapshot.position(call)<snapshot.position(event)<snapshot.position(node)
               for event,_,_ in snapshot.mutations.get((path,scope,base.id),[])):continue
        try:
            imported_references=[]
            schema=literal(snapshot,path,schema_node,references=imported_references)
            result=schema_meanings(schema,snapshot.files,path,projection)
            result['references']+=imported_references
            refs=reference_files(snapshot.files,path)
            result['references']+= [{'path':p,'source_sha256':digest(text),'binding':'explicit_local_file_context'} for p,text in sorted(refs.items())]
            # Plain open(relative) depends on an unavailable runtime working dir.
            if any(isinstance(n,ast.Call) and _name(n.func)=='open' for n in ast.walk(snapshot.trees[path])) and refs:
                result['gaps'].append('schema_open_runtime_directory_unverified')
        except ValueError as exc:
            result={'meanings':[],'gaps':[str(exc)],'references':[]}
        bindings.append({'kind':'jsonschema_validation_binding','binding_anchor':loc(path,call),
                         'schema_anchor':loc(path,schema_node),'projection':projection,**result})
    if bindings:return bindings[-1]
    # An attached parameter document states a declared meaning, never a type by keyword.
    if function and not projection and exact_assignment(snapshot,path,base) is None:
        parameters=[a.arg for a in (*function.args.posonlyargs,*function.args.args,*function.args.kwonlyargs)]
        doc=ast.get_docstring(function,clean=False)
        if base.id in parameters and doc:
            match=re.search(r'^\s*:param\s+(?:\w+\s+)?'+re.escape(base.id)+r':\s*(\S[^\n]*)',doc,re.M)
            if match:
                return {'kind':'attached_parameter_document','binding_anchor':loc(path,function.body[0]),
                        'meanings':[{**leaf('documented_parameter:'+base.id),'definition_sha256':digest(match.group(1))}],
                        'gaps':['document_is_declaration_not_runtime_truth'],'references':[]}
    return None
