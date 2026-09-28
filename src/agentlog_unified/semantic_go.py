"""Exact-revision Go receiver/type/field declarations as metadata, not taint."""
from pathlib import PurePosixPath
import re

from .semantic_ast import Syntax, walk, view
from .semantic_evidence import digest


def field_binding(ctx, anchor, max_files=64):
    path=anchor['path'];s=ctx.syntax[path];use=s.at(anchor)
    if not use or use.type!='selector_expression':return None
    operand=use.child_by_field_name('operand');field=use.child_by_field_name('field')
    if operand.type!='identifier':return {'status':'unresolved','reason':'go_nested_or_dynamic_receiver','use_anchor':anchor}
    name=s.text(operand);declared=None;witness=None
    pair=s.declarations(operand)
    if pair:
        definition,value=pair;declared=definition.child_by_field_name('type');witness=definition
        if declared is None and value and value.type=='composite_literal':declared=value.child_by_field_name('type')
    else:
        fn=s.function(use)
        for group in ('parameters','receiver'):
            params=fn.child_by_field_name(group) if fn else None
            for param in params.named_children if params else []:
                if any(s.text(n)==name for n in param.children_by_field_name('name')):
                    declared=param.child_by_field_name('type');witness=param
    result={'use_anchor':anchor,'field':s.text(field),'status':'unresolved',
            'reason':'go_receiver_type_unresolved','human_confirmed':False,'runtime_verified':False,
            'semantic_scope':'declared_field_metadata_only','sensitivity_inference':'not_performed'}
    if declared is None:return result
    while declared.type=='pointer_type':declared=declared.named_children[0]
    result.update(receiver_declaration=s.anchor(witness),type_anchor=s.anchor(declared),declared_type=view(s.text(declared),path))
    modules=[]
    for p,source in ctx.files.items():
        if PurePosixPath(p).name=='go.mod':
            m=re.search(r'(?m)^\s*module\s+([^\s]+)',source)
            if m:modules.append((PurePosixPath(p).parent,m.group(1).strip('"')))
    directory=PurePosixPath(path).parent;type_name=s.text(declared)
    if any(n.type=='type_spec' and s.function(n) is not None and s.function(n)==s.function(declared)
           and n.start_byte<declared.start_byte and s.text(n.child_by_field_name('name'))==type_name for n in s.nodes):
        return {**result,'reason':'go_local_type_shadow_requires_scope_resolution'}
    if declared.type=='qualified_type':
        package=s.text(declared.child_by_field_name('package'));type_name=s.text(declared.child_by_field_name('name'))
        matches=[]
        for item in s.nodes:
            if item.type!='import_spec':continue
            imported=s.text(item.child_by_field_name('path')).strip('"`')
            alias=s.text(item.child_by_field_name('name')) or imported.rsplit('/',1)[-1]
            if alias==package:matches.append((item,imported))
        if len(matches)!=1:return {**result,'reason':'go_import_binding_ambiguous'}
        imp,imported=matches[0];result.update(import_anchor=s.anchor(imp),import_path=imported)
        targets=[(root,module) for root,module in modules if imported==module or imported.startswith(module+'/')]
        if len(targets)!=1:
            return {**result,'reason':'go_external_or_unavailable_module_definition'}
        root,module=targets[0];directory=root/imported[len(module):].lstrip('/')
        result['module_path']=str(root/'go.mod')
        result['module_source_sha256']=digest(ctx.files[result['module_path']])
        result['module_revision']=ctx.sha
    paths=sorted(p for p in ctx.files if p.endswith('.go') and PurePosixPath(p).parent==directory
                 and (not p.endswith('_test.go') or declared.type!='qualified_type' and path.endswith('_test.go')))
    result['files_examined']=min(len(paths),max_files)
    if len(paths)>max_files:return {**result,'reason':'go_type_file_budget_exceeded'}
    definitions=[]
    for p in paths:
        ss=ctx.syntax.setdefault(p,Syntax(p,ctx.files[p]))
        if ss.root.has_error:continue
        if declared.type!='qualified_type' and [ss.text(n) for n in ss.root.named_children if n.type=='package_clause'] != [s.text(n) for n in s.root.named_children if n.type=='package_clause']:continue
        for d in ss.root.named_children:
            if d.type!='type_declaration':continue
            for spec in d.named_children:
                if spec.type=='type_spec' and ss.text(spec.child_by_field_name('name'))==type_name:
                    definitions.append((ss,spec))
    if len(definitions)!=1:return {**result,'reason':'go_type_definition_missing_or_ambiguous'}
    ss,spec=definitions[0];body=spec.child_by_field_name('type')
    result['type_definition']=ss.anchor(spec)
    if body is None or body.type!='struct_type':return {**result,'reason':'go_alias_or_interface_field_unresolved'}
    fields=[f for f in walk(body) if f.type=='field_declaration' and f.parent.parent==body
            and any(ss.text(n)==result['field'] for n in f.children_by_field_name('name'))]
    if len(fields)!=1:return {**result,'reason':'go_field_missing_ambiguous_or_promoted'}
    f=fields[0]
    return {**result,'status':'bound','reason':'go_explicit_struct_field_definition',
            'field_definition':ss.anchor(f),'field_type_anchor':ss.anchor(f.child_by_field_name('type')),
            'field_type':view(ss.text(f.child_by_field_name('type')),ss.path)}
