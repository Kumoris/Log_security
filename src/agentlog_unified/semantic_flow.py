"""Finite structural control and alias checks, without executing expressions."""
import ast


def controls(snapshot, path, node):
    result=[]; child=node; parent=snapshot.parents[path].get(child)
    while parent is not None and not isinstance(parent,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Module)):
        if isinstance(parent,(ast.If,ast.IfExp,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.With,ast.AsyncWith,ast.Match,ast.ExceptHandler)):
            field=next((k for k,v in ast.iter_fields(parent) if v is child or isinstance(v,list) and child in v),None)
            result.append((parent,field))
        child=parent;parent=snapshot.parents[path].get(parent)
    return result


def conditional_between(snapshot,path,definition,use):
    """A definition in the same enclosing arm can dominate a later use."""
    return not set(controls(snapshot,path,definition)).issubset(controls(snapshot,path,use))


def exclusive_branches(snapshot,path,left,right):
    a=dict(controls(snapshot,path,left));b=dict(controls(snapshot,path,right))
    return any(isinstance(n,(ast.If,ast.IfExp)) and {a[n],b[n]}=={'body','orelse'} for n in a.keys() & b.keys())


def branch_assignments(snapshot,path,node):
    """Two explicit straight-line if arms; no loops or inferred predicates."""
    scope=snapshot.symbol(path,node);parents=snapshot.parents[path]
    choices=[]
    for branch in ast.walk(snapshot.trees[path]):
        if not isinstance(branch,ast.If) or snapshot.symbol(path,branch)!=scope or branch.end_lineno>=node.lineno:
            continue
        if conditional_between(snapshot,path,branch,node):continue
        arms=[]
        for body in (branch.body,branch.orelse):
            # Keep the first implementation to one explicit assignment per arm.
            assignments=[s for s in body if isinstance(s,(ast.Assign,ast.AnnAssign))
                and any(isinstance(t,ast.Name) and t.id==node.id for t in (s.targets if isinstance(s,ast.Assign) else [s.target]))]
            if len(body)!=1 or len(assignments)!=1 or assignments[0].value is None:break
            arms.append(assignments[0])
        if len(arms)==2:choices.append((branch,arms))
    if not choices:return None
    branch,arms=max(choices,key=lambda item:snapshot.position(item[0]))
    later=[a for a in snapshot.assignments.get((path,scope,node.id),[]) if branch.end_lineno<a.lineno<node.lineno]
    if later:return None
    # Unknown calls or writes after the join cannot be ignored.
    if any(branch.end_lineno<e.lineno<node.lineno for (p,sc,_),events in snapshot.mutations.items()
           if p==path and sc==scope for e,_,_ in events):
        return None
    return branch,arms


def visible_mutations(snapshot,path,node,assignment):
    """Include writes through explicit name aliases; rebindings break identity."""
    scope=snapshot.symbol(path,node);parents=snapshot.parents[path]
    def root(name,at,depth=0):
        if depth>8:return None
        enclosing=set();p=at
        while p is not None:enclosing.add(p);p=parents.get(p)
        earlier=[a for a in snapshot.assignments.get((path,scope,name),[])
                 if snapshot.position(a)<snapshot.position(at) and a not in enclosing]
        if not earlier:return (name,None)
        a=max(earlier,key=snapshot.position)
        if conditional_between(snapshot,path,a,at):return None
        if isinstance(a.value,ast.Name):return root(a.value.id,a.value,depth+1)
        return (name,a)
    origin=root(node.id,node);enclosing=set();p=node
    while p is not None:enclosing.add(p);p=parents.get(p)
    result=[]
    for (pp,sc,name),events in snapshot.mutations.items():
        if pp!=path or sc!=scope:continue
        for event,keys,kind in events:
            if event in enclosing or not snapshot.position(assignment)<snapshot.position(event)<snapshot.position(node):continue
            if exclusive_branches(snapshot,path,event,node):continue
            candidate=root(name,event)
            if name==node.id or origin is not None and candidate==origin:
                result.append((event,keys,kind))
            elif candidate is None:
                # A conditional alias may refer to this object. Preserve uncertainty.
                result.append((event,keys,'alias_identity_unresolved'))
    # A write after this use may reach the next iteration. Do not mistake a
    # fresh-looking source position for the first runtime iteration.
    for loop,_ in controls(snapshot,path,node):
        if not isinstance(loop,(ast.For,ast.AsyncFor,ast.While)) or any(c is loop for c,_ in controls(snapshot,path,assignment)):continue
        for (pp,sc,name),events in snapshot.mutations.items():
            if pp!=path or sc!=scope:continue
            for event,keys,kind in events:
                if event not in enclosing and node.lineno<=event.lineno<=loop.end_lineno and (name==node.id or origin is not None and root(name,event)==origin):
                    result.append((event,keys,'loop_carried_write_unresolved'))
    for event in ast.walk(snapshot.trees[path]):
        if not isinstance(event,ast.Assign) or snapshot.symbol(path,event)!=scope or not snapshot.position(assignment)<snapshot.position(event)<snapshot.position(node):continue
        if exclusive_branches(snapshot,path,event,node):continue
        if isinstance(event.value,(ast.Dict,ast.List,ast.Tuple,ast.Set)) and any(isinstance(n,ast.Name) and root(n.id,n)==origin for n in ast.walk(event.value)):
            result.append((event,[],'container_alias_unresolved'))
    return sorted(result,key=lambda item:snapshot.position(item[0]))
