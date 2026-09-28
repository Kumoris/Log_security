"""Tree-sitter use/binding witnesses for JS, TS, Go and bounded Java syntax."""
from __future__ import annotations

import posixpath
from pathlib import Path

from .semantic_evidence import digest, leaf
from .storage import stable_id

FUNCTIONS={'function_declaration','function_expression','arrow_function','method_declaration','method_definition','func_literal'}
BLOCKS={'statement_block','block','program','source_file'}
CONTROL={'if_statement','for_statement','for_in_statement','switch_statement','select_statement','try_statement','while_statement'}
IDENTIFIERS={'identifier','property_identifier','field_identifier','shorthand_property_identifier','shorthand_property_identifier_pattern'}
STRINGS={'string','interpreted_string_literal','raw_string_literal','template_string','string_literal','character_literal'}
CALLS={'call_expression','method_invocation'}


def walk(node):
    yield node
    for child in node.named_children:yield from walk(child)


class Syntax:
    def __init__(self,path,source):
        from tree_sitter import Language,Parser
        import tree_sitter_javascript as js
        import tree_sitter_typescript as ts
        import tree_sitter_go as go
        import tree_sitter_java as java
        suffix=Path(path).suffix
        language=java.language() if suffix=='.java' else go.language() if suffix=='.go' else ts.language_tsx() if suffix=='.tsx' else ts.language_typescript() if suffix=='.ts' else js.language()
        self.path,self.source,self.raw=path,source,source.encode()
        self.language=Language(language)
        self.parser=Parser(self.language)
        self.tree=self.parser.parse(self.raw)
        self.root=self.tree.root_node
        self.nodes=list(walk(self.root))

    def text(self,node):return self.raw[node.start_byte:node.end_byte].decode() if node else ''

    def anchor(self,node):
        return {'path':self.path,'line':node.start_point.row+1,'end_line':node.end_point.row+1,
                'column':node.start_point.column,'end_column':node.end_point.column,'node_kind':node.type,
                'start_byte':node.start_byte,'end_byte':node.end_byte,'parser':'tree_sitter'}

    def at(self,anchor):return next((n for n in self.nodes if self.anchor(n)==anchor),None)

    def function(self,node):
        parent=node.parent
        while parent and parent.type not in FUNCTIONS:parent=parent.parent
        return parent

    def scope(self,node):
        parent=self.function(node)
        return '<module>' if parent is None else self.text(parent.child_by_field_name('name'))+'@'+str(parent.start_byte)

    def conditional(self,node,use=None):
        use_ancestors=set();p=use
        while p:
            use_ancestors.add(p.id);p=p.parent
        parent=node.parent
        while parent and parent.type not in FUNCTIONS:
            if parent.type in CONTROL:
                child=node
                while child.parent!=parent:child=child.parent
                if use is None or child.id not in use_ancestors:return True
            parent=parent.parent
        return False

    def declarations(self,node):
        """Latest visible lexical definition; an uncertain write blocks fallback."""
        name=self.text(node);found=[]
        ancestors=set();parent=node.parent
        while parent:
            ancestors.add(parent.id);parent=parent.parent
        for candidate in self.nodes:
            if candidate.start_byte>=node.start_byte or self.scope(candidate)!=self.scope(node):continue
            if candidate.type in {'variable_declarator','var_spec','const_spec'}:
                target=candidate.child_by_field_name('name');value=candidate.child_by_field_name('value')
            elif candidate.type in {'short_var_declaration','assignment_statement','assignment_expression','augmented_assignment_expression'}:
                target=candidate.child_by_field_name('left');value=candidate.child_by_field_name('right')
            else:continue
            targets=target.named_children if target and target.type=='expression_list' else [target]
            if not any(t and self.text(t)==name for t in targets):continue
            if candidate.id in ancestors:continue  # RHS does not see its own declaration
            block=candidate.parent
            while block and block.type not in BLOCKS:block=block.parent
            if block and block.id not in ancestors:
                if candidate.type in {'assignment_statement','assignment_expression','augmented_assignment_expression'}:return (candidate,None)
                continue
            if target is None or len(targets)!=1 or self.conditional(candidate,node):return (candidate,None)
            if value and value.type=='expression_list':value=value.named_children[0] if len(value.named_children)==1 else None
            found.append((candidate,value))
        return max(found,key=lambda pair:pair[0].start_byte) if found else None

    def mutation_gap(self,node):
        """Fail open on member writes, updates and value escapes before this use."""
        name=self.text(node);ancestors=set();parent=node.parent
        while parent:ancestors.add(parent.id);parent=parent.parent
        declaration=self.declarations(node)
        lower=declaration[0].end_byte if declaration else 0
        for event in self.nodes:
            if event.id in ancestors or not lower<event.start_byte<node.start_byte or self.scope(event)!=self.scope(node):continue
            if event.type in {'update_expression','inc_statement','dec_statement'} and any(self.text(n)==name for n in walk(event)):
                return True
            if event.type in {'assignment_expression','assignment_statement','augmented_assignment_expression'}:
                left=event.child_by_field_name('left')
                if left and any(n.type in IDENTIFIERS and self.text(n)==name for n in walk(left)):return True
            if event.type in CALLS:
                arguments=event.child_by_field_name('arguments')
                if arguments and any(n.type in IDENTIFIERS and self.text(n)==name for n in walk(arguments)):return True
        return False


def use_sites(entity,source):
    syntax=Syntax(entity['path'],source)
    if syntax.root.has_error:return [],[{'reason':'tree_sitter_parse_error','path':entity['path']}]
    calls=[n for n in syntax.nodes if n.type in CALLS and n.start_point.row+1==entity['start_line']
           and n.end_point.row+1==entity['end_line'] and syntax.text(n).strip()==entity['statement'].strip().rstrip(';')]
    if len(calls)!=1:return [],[{'reason':'tree_sitter_log_call_anchor_ambiguous','path':entity['path']}]
    args=calls[0].child_by_field_name('arguments');result=[];excluded=[]
    for index,arg in enumerate(args.named_children if args else []):
        if index==0 and arg.type in STRINGS and not any(n.type=='template_substitution' for n in walk(arg)):
            excluded.append({'reason':'fixed_log_message_template','path':entity['path'],'line':arg.start_point.row+1});continue
        values=[]
        if arg.type=='object':
            for field in arg.named_children:
                value=field.child_by_field_name('value') if field.type=='pair' else field
                if value:values.append(value)
        elif arg.type=='template_string':
            values=[c for n in walk(arg) if n.type=='template_substitution' for c in n.named_children]
        else:values=[arg]
        for value in values:
            name=syntax.text(value) if value.type in IDENTIFIERS|{'member_expression','selector_expression','field_access'} else 'expression'
            result.append({'field':name,'anchor':syntax.anchor(value),'field_origin':'tree_sitter_log_argument','line':value.start_point.row+1})
            for nested in walk(value):
                if nested==value or nested.type!='identifier':continue
                parent=nested.parent
                if parent.type in CALLS and (parent.child_by_field_name('function')==nested or parent.child_by_field_name('name')==nested):continue
                result.append({'field':syntax.text(nested),'anchor':syntax.anchor(nested),'field_origin':'nested_expression_input',
                               'line':nested.start_point.row+1,'output_expression_anchor':syntax.anchor(value)})
    return list({stable_id(v['anchor']):v for v in result}.values()),excluded


def view(source,path):
    """Preserve syntax/identifiers, mask every literal/comment in public exports."""
    syntax=Syntax(path,source);ranges=[]
    hidden=(STRINGS-{'template_string'})|{'string_fragment','number','int_literal','float_literal','imaginary_literal','rune_literal','comment','regex'}
    def visit(n):
        if n.type in hidden or n.type.endswith('_literal') or n.type in {'line_comment','block_comment'}:ranges.append((n.start_byte,n.end_byte));return
        for child in n.named_children:visit(child)
    visit(syntax.root);raw=syntax.raw
    for start,end in reversed(ranges):
        raw=raw[:start]+b'<literal>'+b'\n'*raw[start:end].count(b'\n')+raw[end:]
    return raw.decode()


def analyze(files,repository,revision,path,anchor,*,max_chars=16000,one_hop=True,max_hops=1,**_):
    syntaxes={p:Syntax(p,t) for p,t in files.items() if Path(p).suffix in {'.js','.mjs','.cjs','.jsx','.ts','.tsx','.go','.java'}}
    syntax=syntaxes[path];node=syntax.at(anchor);used=0;gaps=[]
    def proof(s,n,op,children=(),**details):
        nonlocal used
        used+=len(s.text(n))
        if used>max_chars:op='unknown';children=[];details={'reason':'context_budget_exceeded'}
        if op=='unknown':gaps.append(details['reason'])
        return {'op':op,'anchor':s.anchor(n),'sha':revision,'source_sha256':digest(s.source),
                'snippet_sha256':digest(s.text(n)),'scope':s.scope(n),'children':list(children),**details}
    def resolve(s,n,depth=0,bound=None,hops=0):
        bound=bound or {}
        def child(q,ss=s,bb=bound,hh=hops):return resolve(ss,q,depth+1,bb,hh)
        if depth>16:return proof(s,n,'unknown',reason='binding_depth_exceeded')
        if n.has_error:return proof(s,n,'unknown',reason='tree_sitter_parse_error')
        if n.type in {'true','false','null','nil'}:return proof(s,n,'fixed_boolean_null')
        if n.type in IDENTIFIERS:
            if s.mutation_gap(n):return proof(s,n,'unknown',reason='mutation_or_escape_unresolved')
            declaration=s.declarations(n)
            if declaration:
                definition,value=declaration
                if value:return proof(s,n,'alias',[child(value)],definition=s.anchor(definition))
                return proof(s,n,'unknown',reason='conditional_or_multiple_assignment')
            if s.text(n) in bound:return proof(s,n,'bound',[bound[s.text(n)]])
            function=s.function(n)
            params=function.child_by_field_name('parameters') if function else None
            for param in params.named_children if params else []:
                names=param.children_by_field_name('name') or [param.child_by_field_name('pattern') or param]
                if any(s.text(name)==s.text(n) for name in names):
                    annotation=param.child_by_field_name('type')
                    if annotation:return proof(s,n,'parameter',[child(annotation)],definition=s.anchor(param))
            return proof(s,n,'unknown',reason='unresolved_scoped_binding')
        if n.type in {'type_annotation','parenthesized_expression','await_expression','pointer_type'}:
            if len(n.named_children)==1:return proof(s,n,'transparent',[child(n.named_children[0])])
        if n.type in {'type_identifier','qualified_type'}:
            definitions=[d for d in s.nodes if d.type in {'type_alias_declaration','interface_declaration','type_spec'} and s.scope(d) in {'<module>',s.scope(n)} and s.text(d.child_by_field_name('name'))==s.text(n)]
            if len(definitions)==1:
                definition=definitions[0];body=definition.child_by_field_name('body') or definition.child_by_field_name('type')
                fields=[f for f in walk(body) if f.type in {'property_signature','field_declaration'}] if body else []
                if fields:
                    return proof(s,n,'model',[child(f.child_by_field_name('type')) for f in fields],
                                 fields=[s.text(f.child_by_field_name('name')) for f in fields],definition=s.anchor(definition))
                return proof(s,n,'nominal',definition=s.anchor(definition),type_name=s.text(n))
            return proof(s,n,'unknown',reason='type_definition_missing_or_primitive')
        if n.type in {'member_expression','selector_expression','subscript_expression','index_expression','field_access'}:
            obj=n.child_by_field_name('object') or n.child_by_field_name('operand')
            field=n.child_by_field_name('property') or n.child_by_field_name('field') or n.child_by_field_name('index')
            if obj and field:
                key=s.text(field)
                if field.type in STRINGS:key=key[1:-1]
                elif n.type in {'subscript_expression','index_expression'}:
                    return proof(s,n,'unknown',reason='dynamic_projection_unresolved')
                return proof(s,n,'projection',[child(obj)],field=key)
        if n.type=='object':
            fields=[];children=[]
            for item in n.named_children:
                key=item.child_by_field_name('key');value=item.child_by_field_name('value')
                if key and value:fields.append(s.text(key).strip('"\''));children.append(child(value))
                elif item.type=='shorthand_property_identifier':fields.append(s.text(item));children.append(child(item))
                else:return proof(s,n,'unknown',reason='object_spread_or_dynamic_key')
            return proof(s,n,'object',children,fields=fields)
        if n.type=='call_expression' and one_hop and hops<max_hops:
            callee=n.child_by_field_name('function');args=n.child_by_field_name('arguments')
            # Same-module explicit functions only; dynamic/member dispatch stays pending.
            targets=[f for f in s.nodes if f.type=='function_declaration' and s.text(f.child_by_field_name('name'))==s.text(callee)]
            if len(targets)==1 and callee.type=='identifier':
                fn=targets[0];body=fn.child_by_field_name('body');params=fn.child_by_field_name('parameters')
                returns=[r for r in walk(body) if r.type=='return_statement']
                statements=[q for q in walk(body) if q.type.endswith('_statement') and q.type!='statement_list']
                if len(returns)==1 and all(q.type=='return_statement' for q in statements):
                    values=returns[0].named_children
                    if len(values)==1 and values[0].type=='expression_list':values=values[0].named_children
                    parameter_names=[s.text(p.child_by_field_name('pattern') or p.child_by_field_name('name') or p) for p in params.named_children]
                    if len(values)==1 and len(parameter_names)==len(args.named_children) and all(name.isidentifier() for name in parameter_names):
                        bindings={name:child(arg) for name,arg in zip(parameter_names,args.named_children)}
                        return proof(s,n,'call',[child(values[0],bb=bindings,hh=hops+1)],definition=s.anchor(fn),bindings=bindings)
            return proof(s,n,'unknown',reason='call_or_effect_unresolved')
        return proof(s,n,'unknown',reason='unsupported_ast_expression:'+n.type)
    root=resolve(syntax,node) if node else None
    result={'proof':root,'proposal':propose(root),'gaps':gaps,'context_chars':min(used,max_chars),'name_only_hints':[]}
    result['review']=review(files,repository,revision,root,max_chars=max_chars,max_hops=max_hops,one_hop=one_hop)
    return result


def propose(proof):
    """Stage A reads extraction witnesses; Stage B reparses raw source separately."""
    if not proof:return []
    op=proof['op']
    if op=='nominal':return [leaf('declared_type:'+proof['type_name'])]
    if op=='fixed_boolean_null':return [leaf('fixed_null_or_boolean_literal',nonsensitive=True)]
    if op=='projection':
        def project(p):
            if p['op'] in {'alias','parameter','transparent','bound','call'}:return project(p['children'][0])
            if p['op'] in {'model','object'} and proof['field'] in p['fields']:return propose(p['children'][p['fields'].index(proof['field'])])
            return []
        return project(proof['children'][0])
    return [v for child in proof.get('children',[]) for v in propose(child)]


def review(files,repository,revision,proof,**budgets):
    """Reparse original sources and check every witness independently of labels.

    Syntax relations are regenerated, then meanings are derived from verified
    declaration nodes. Neither proposal strings nor claimed types are accepted.
    """
    syntaxes={};reasons=[];checked=[]
    def evaluate(p):
        if not p:reasons.append('history_or_use_missing');return []
        a=p['anchor'];path=a['path']
        if path not in syntaxes:syntaxes[path]=Syntax(path,files.get(path,''))
        s=syntaxes[path];n=s.at(a)
        if n is None or p['sha']!=revision or p['source_sha256']!=digest(s.source) or p['snippet_sha256']!=digest(s.text(n)) or p['scope']!=s.scope(n):
            reasons.append('history_or_scope_mismatch');return []
        checked.append(a);op=p['op'];children=p.get('children',[])
        if op=='unknown':reasons.append(p['reason']);return []
        if op=='fixed_boolean_null' and n.type in {'true','false','null','nil'}:return [leaf('fixed_null_or_boolean_literal',nonsensitive=True)]
        if op=='alias':
            pair=s.declarations(n)
            if s.mutation_gap(n) or not pair or pair[1] is None or s.anchor(pair[0])!=p['definition'] or children[0]['anchor']!=s.anchor(pair[1]):
                reasons.append('assignment_binding_mismatch');return []
        elif op=='parameter':
            param=s.at(p['definition']);fn=s.function(n)
            if s.mutation_gap(n) or not fn or not param or not any(s.text(v)==s.text(n) for v in (param.children_by_field_name('name') or [param.child_by_field_name('pattern') or param])) or param not in fn.child_by_field_name('parameters').named_children or children[0]['anchor']!=s.anchor(param.child_by_field_name('type')):
                reasons.append('parameter_binding_mismatch');return []
        elif op=='nominal':
            if n.type not in {'type_identifier','qualified_type'}:reasons.append('nominal_node_kind_mismatch');return []
            definition=s.at(p['definition'])
            if not definition or definition.type not in {'type_alias_declaration','type_spec','interface_declaration'} or s.text(definition.child_by_field_name('name'))!=s.text(n) or p['type_name']!=s.text(n):
                reasons.append('nominal_definition_mismatch');return []
            return [leaf('declared_type:'+s.text(n))]
        elif op=='projection':
            obj=n.child_by_field_name('object') or n.child_by_field_name('operand')
            field=n.child_by_field_name('property') or n.child_by_field_name('field') or n.child_by_field_name('index')
            if not obj or not field or children[0]['anchor']!=s.anchor(obj) or p['field']!=s.text(field).strip('"\''):
                reasons.append('projection_binding_mismatch');return []
            def project(q):
                if q['op'] in {'alias','parameter','transparent','bound','call'}:return project(q['children'][0])
                if q['op'] in {'model','object'} and p['field'] in q['fields']:return evaluate(q['children'][q['fields'].index(p['field'])])
                reasons.append('projected_field_unresolved');return []
            start=len(reasons);evaluate(children[0])
            if all(r in {'type_definition_missing_or_primitive','unresolved_scoped_binding','unsupported_ast_expression:predefined_type'} for r in reasons[start:]):del reasons[start:]
            return project(children[0])
        elif op=='model':
            if n.type not in {'type_identifier','qualified_type'}:reasons.append('model_node_kind_mismatch');return []
            definition=s.at(p['definition']);body=definition.child_by_field_name('body') or definition.child_by_field_name('type') if definition else None
            fields=[f for f in walk(body) if f.type in {'property_signature','field_declaration'}] if body else []
            if not definition or s.text(definition.child_by_field_name('name'))!=s.text(n) or p['fields']!=[s.text(f.child_by_field_name('name')) for f in fields] or [c['anchor'] for c in children]!=[s.anchor(f.child_by_field_name('type')) for f in fields]:
                reasons.append('model_fields_mismatch');return []
        elif op=='transparent':
            if len(n.named_children)!=1 or children[0]['anchor']!=s.anchor(n.named_children[0]):reasons.append('transparent_binding_mismatch');return []
        elif op=='object':
            values=[f.child_by_field_name('value') or f for f in n.named_children]
            keys=[s.text(f.child_by_field_name('key') or f).strip('"\'') for f in n.named_children]
            if n.type!='object' or p['fields']!=keys or [c['anchor'] for c in children]!=[s.anchor(v) for v in values]:reasons.append('object_binding_mismatch');return []
        elif op in {'bound','call'}:
            # Keep call expansion useful as context; cross-frame proof validation
            # is deliberately pending rather than implicitly trusting substitutions.
            reasons.append('interprocedural_ast_binding_requires_review')
        else:reasons.append('unverified_ast_operation');return []
        return [v for c in children for v in evaluate(c)]
    values=list({stable_id(v):v for v in evaluate(proof)}.values())
    return {'status':'unsupported' if any(r.endswith('mismatch') for r in reasons) else 'ambiguous' if reasons or not values else 'supported',
            'reasons':sorted(set(reasons)) or ['raw_tree_sitter_binding_witnesses_checked'],
            'derived_meanings':values,'checked_anchors':checked,'method':'independent_tree_sitter_evidence_replay',
            'model_stage':'not_run','model':None,'human_confirmed':False}


def public_proof(proof,files):
    if proof is None:return None
    result={k:v for k,v in proof.items() if k not in {'children','bindings'}}
    a=proof['anchor'];s=Syntax(a['path'],files.get(a['path'],''));node=s.at(a)
    result['code_view']=view(s.text(node),a['path']) if node else '<missing>'
    result['code_view_is_verbatim']=False
    result['children']=[public_proof(p,files) for p in proof.get('children',[])]
    if 'bindings' in proof:result['bindings']={k:public_proof(v,files) for k,v in proof['bindings'].items()}
    return result
